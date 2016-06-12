# -*- coding: utf-8 -*-

""" OneLogin_Saml2_Authn_Request class

Copyright (c) 2014, OneLogin, Inc.
All rights reserved.

AuthNRequest class of OneLogin's Python Toolkit.

"""
import logging

log = logging.getLogger(__name__)

from base64 import b64encode

from onelogin.saml2.utils import OneLogin_Saml2_Utils
from onelogin.saml2.constants import OneLogin_Saml2_Constants
from onelogin.saml2.errors import OneLogin_Saml2_Error

from xml.dom.minidom import Document, parseString

import dm.xmlsec.binding as xmlsec
from dm.xmlsec.binding.tmpl import Signature

from lxml.etree import tostring, fromstring


class OneLogin_Saml2_Authn_Request(object):
    """

    This class handles an AuthNRequest. It builds an
    AuthNRequest object.

    """

    def __init__(self, settings, force_authn=False, is_passive=False, set_nameid_policy=True):
        """
        Constructs the AuthnRequest object.

        :param settings: OSetting data
        :type return_to: OneLogin_Saml2_Settings

        :param force_authn: Optional argument. When true the AuthNReuqest will set the ForceAuthn='true'.
        :type force_authn: bool

        :param is_passive: Optional argument. When true the AuthNReuqest will set the Ispassive='true'.
        :type is_passive: bool

        :param set_nameid_policy: Optional argument. When true the AuthNReuqest will set a nameIdPolicy element.
        :type set_nameid_policy: bool
        """
        self.__settings = settings

        sp_data = self.__settings.get_sp_data()
        idp_data = self.__settings.get_idp_data()
        security = self.__settings.get_security_data()

        uid = OneLogin_Saml2_Utils.generate_unique_id()
        self.__id = uid
        issue_instant = OneLogin_Saml2_Utils.parse_time_to_SAML(OneLogin_Saml2_Utils.now())

        destination = idp_data['singleSignOnService']['url']

        provider_name_str = ''
        organization_data = settings.get_organization()
        if isinstance(organization_data, dict) and organization_data:
            langs = organization_data.keys()
            if 'en-US' in langs:
                lang = 'en-US'
            else:
                lang = langs[0]
            if 'displayname' in organization_data[lang] and organization_data[lang]['displayname'] is not None:
                provider_name_str = "\n" + '    ProviderName="%s"' % organization_data[lang]['displayname']

        force_authn_str = ''
        if force_authn is True:
            force_authn_str = "\n" + '    ForceAuthn="true"'

        is_passive_str = ''
        if is_passive is True:
            is_passive_str = "\n" + '    IsPassive="true"'

        nameid_policy_str = ''
        if set_nameid_policy:
            name_id_policy_format = sp_data['NameIDFormat']
            if 'wantNameIdEncrypted' in security and security['wantNameIdEncrypted']:
                name_id_policy_format = OneLogin_Saml2_Constants.NAMEID_ENCRYPTED

            nameid_policy_str = """
    <samlp:NameIDPolicy
        Format="%s"
        AllowCreate="true" />""" % name_id_policy_format

        requested_authn_context_str = ''
        if 'requestedAuthnContext' in security.keys() and security['requestedAuthnContext'] is not False:
            authn_comparison = 'exact'
            if 'requestedAuthnContextComparison' in security.keys():
                authn_comparison = security['requestedAuthnContextComparison']

            if security['requestedAuthnContext'] is True:
                requested_authn_context_str = "\n" + """    <samlp:RequestedAuthnContext Comparison="%s">
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
    </samlp:RequestedAuthnContext>""" % authn_comparison
            else:
                requested_authn_context_str = "\n" + '     <samlp:RequestedAuthnContext Comparison="%s">' % authn_comparison
                for authn_context in security['requestedAuthnContext']:
                    requested_authn_context_str += '<saml:AuthnContextClassRef>%s</saml:AuthnContextClassRef>' % authn_context
                requested_authn_context_str += '    </samlp:RequestedAuthnContext>'

        attr_consuming_service_str = ''
        if 'attributeConsumingService' in sp_data and sp_data['attributeConsumingService']:
            attr_consuming_service_str = 'AttributeConsumingServiceIndex="1"'

        request = """<samlp:AuthnRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="%(id)s"
    Version="2.0"%(provider_name)s%(force_authn_str)s%(is_passive_str)s
    IssueInstant="%(issue_instant)s"
    Destination="%(destination)s"
    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
    AssertionConsumerServiceURL="%(assertion_url)s"
    %(attr_consuming_service_str)s>
    <saml:Issuer>%(entity_id)s</saml:Issuer>%(nameid_policy_str)s%(requested_authn_context_str)s
</samlp:AuthnRequest>""" % \
                  {
                      'id': uid,
                      'provider_name': provider_name_str,
                      'force_authn_str': force_authn_str,
                      'is_passive_str': is_passive_str,
                      'issue_instant': issue_instant,
                      'destination': destination,
                      'assertion_url': sp_data['assertionConsumerService']['url'],
                      'entity_id': sp_data['entityId'],
                      'nameid_policy_str': nameid_policy_str,
                      'requested_authn_context_str': requested_authn_context_str,
                      'attr_consuming_service_str': attr_consuming_service_str
                  }

        #from https://github.com/onelogin/python-saml/pull/78. credit to @tachang
        # Only the urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST binding gets the enveloped signature
        if settings.get_idp_data()['singleSignOnService'].get('binding',
                                                              None) == 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST' and \
                        security['authnRequestsSigned'] is True:

            log.debug("Generating AuthnRequest using urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST binding")

            if 'signatureAlgorithm' in security:
                key = settings.get_sp_key()
                if not key:
                    raise OneLogin_Saml2_Error("Attempt to sign the AuthnRequest but unable to load the SP private key")
                cert = settings.get_sp_cert()
                if not key:
                    raise OneLogin_Saml2_Error("Attempt to sign the AuthnRequest but unable to load the SP cert")
                doc = parseString(request)
                security_algo = security['signatureAlgorithm']
                self.__authn_request = OneLogin_Saml2_Utils.add_sign(doc, key, cert, sign_algorithm=security_algo, debug=True)

                # xmlsec.initialize()
                # xmlsec.set_error_callback(self.print_xmlsec_errors)
                #
                # sign_algorithm_transform_map = {
                #     OneLogin_Saml2_Constants.DSA_SHA1: xmlsec.TransformDsaSha1,
                #     OneLogin_Saml2_Constants.RSA_SHA1: xmlsec.TransformRsaSha1,
                #     OneLogin_Saml2_Constants.RSA_SHA256: xmlsec.TransformRsaSha256,
                #     OneLogin_Saml2_Constants.RSA_SHA384: xmlsec.TransformRsaSha384,
                #     OneLogin_Saml2_Constants.RSA_SHA512: xmlsec.TransformRsaSha512
                # }
                # sign_algorithm_transform = sign_algorithm_transform_map.get(security_algo, xmlsec.TransformRsaSha1)
                #
                # signature = Signature(xmlsec.TransformExclC14N, sign_algorithm_transform)
                #
                # doc = fromstring(request)
                #
                # # ID attributes different from xml:id must be made known by the application through a call
                # # to the addIds(node, ids) function defined by xmlsec.
                # xmlsec.addIDs(doc, ['ID'])
                #
                # doc.insert(0, signature)
                #
                # ref = signature.addReference(xmlsec.TransformSha1, uri="#%s" % uid)
                # ref.addTransform(xmlsec.TransformEnveloped)
                # ref.addTransform(xmlsec.TransformExclC14N)
                #
                # key_info = signature.ensureKeyInfo()
                # key_info.addKeyName()
                # key_info.addX509Data()
                #
                # dsig_ctx = xmlsec.DSigCtx()
                #
                # sign_key = xmlsec.Key.loadMemory(key, xmlsec.KeyDataFormatPem, None)
                #
                # from tempfile import NamedTemporaryFile
                # cert_file = NamedTemporaryFile(delete=True)
                # cert_file.write(cert)
                # cert_file.seek(0)
                #
                # sign_key.loadCert(cert_file.name, xmlsec.KeyDataFormatPem)
                #
                # dsig_ctx.signKey = sign_key
                #
                # # Note: the assignment below effectively copies the key
                # dsig_ctx.sign(signature)
                #
                # self.__authn_request = tostring(doc)
                # log.debug("Generated AuthnRequest: {}".format(self.__authn_request))


            else:
                self.__authn_request = request

            log.debug("Generated AuthnRequest: {}".format(self.__authn_request))

            # xmlsec.initialize()
            # xmlsec.set_error_callback(self.print_xmlsec_errors)
            #
            # signature = Signature(xmlsec.TransformExclC14N, xmlsec.TransformRsaSha1)
            #
            # doc = fromstring(request)
            #
            # # ID attributes different from xml:id must be made known by the application through a call
            # # to the addIds(node, ids) function defined by xmlsec.
            # xmlsec.addIDs(doc, ['ID'])
            #
            # doc.insert(0, signature)
            #
            # ref = signature.addReference(xmlsec.TransformSha1, uri="#%s" % uid)
            # ref.addTransform(xmlsec.TransformEnveloped)
            # ref.addTransform(xmlsec.TransformExclC14N)
            #
            # key_info = signature.ensureKeyInfo()
            # key_info.addKeyName()
            # key_info.addX509Data()
            #
            # # Load the key into the xmlsec context
            # key = settings.get_sp_key()
            # if not key:
            #     raise OneLogin_Saml2_Error("Attempt to sign the AuthnRequest but unable to load the SP private key")
            #
            # dsig_ctx = xmlsec.DSigCtx()
            #
            # sign_key = xmlsec.Key.loadMemory(key, xmlsec.KeyDataFormatPem, None)
            #
            # from tempfile import NamedTemporaryFile
            # cert_file = NamedTemporaryFile(delete=True)
            # cert_file.write(settings.get_sp_cert())
            # cert_file.seek(0)
            #
            # sign_key.loadCert(cert_file.name, xmlsec.KeyDataFormatPem)
            #
            # dsig_ctx.signKey = sign_key
            #
            # # Note: the assignment below effectively copies the key
            # dsig_ctx.sign(signature)

            #self.__authn_request = tostring(doc)
            #log.debug("Generated AuthnRequest: {}".format(self.__authn_request))

        else:
            self.__authn_request = request

    def print_xmlsec_errors(self, filename, line, func, errorObject, errorSubject, reason, msg):
        # this would give complete but often not very usefull) information
        print "%(filename)s:%(line)d(%(func)s) error %(reason)d obj=%(errorObject)s subject=%(errorSubject)s: %(msg)s" % locals()
        # the following prints if we get something with relation to the application

        info = []

        if errorObject != "unknown":
            info.append("obj=" + errorObject)

        if errorSubject != "unknown":
            info.append("subject=" + errorSubject)

        if msg.strip():
            info.append("msg=" + msg)

        if info:
            print "%s:%d(%s)" % (filename, line, func), " ".join(info)

    def get_request(self, deflate=True):
        """
        Returns unsigned AuthnRequest.
        :param deflate: It makes the deflate process optional
        :type: bool
        :return: AuthnRequest maybe deflated and base64 encoded
        :rtype: str object
        """
        if deflate:
            request = OneLogin_Saml2_Utils.deflate_and_base64_encode(self.__authn_request)
        else:
            request = b64encode(self.__authn_request)
        return request

    def get_id(self):
        """
        Returns the AuthNRequest ID.
        :return: AuthNRequest ID
        :rtype: string
        """
        return self.__id
