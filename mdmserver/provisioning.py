from __future__ import annotations

import base64
import secrets

from . import crypto
from .soap import url_encode_subject
from .xmlutil import xml_escape


def build_provisioning_document_b64(config, issued_cert: crypto.IssuedCertificate, email: str, device_id: str) -> str:
    xml = build_provisioning_document(config, issued_cert, email, device_id)
    return base64.b64encode(xml.encode("utf-8")).decode("ascii")


def build_provisioning_document(config, issued_cert: crypto.IssuedCertificate, email: str, device_id: str) -> str:
    root_thumb = crypto.cert_thumbprint_from_file(config.ca_cert_file)
    root_b64 = crypto.pem_cert_to_der_b64(config.ca_cert_file)
    cert_store_scope = "System" if config.enrollment_context.lower() == "device" else "User"
    cert_search = f"Subject={url_encode_subject(issued_cert.subject)}&Stores=My%5C{cert_store_scope}"
    client_secret = secrets.token_urlsafe(24)
    server_secret = secrets.token_urlsafe(24)
    server_nonce = base64.b64encode(secrets.token_bytes(16)).decode("ascii")

    return f"""<wap-provisioningdoc version="1.1">
  <characteristic type="CertificateStore">
    <characteristic type="Root">
      <characteristic type="System">
        <characteristic type="{xml_escape(root_thumb)}">
          <parm name="EncodedCertificate" value="{xml_escape(root_b64)}" />
        </characteristic>
      </characteristic>
    </characteristic>
  </characteristic>
  <characteristic type="CertificateStore">
    <characteristic type="My">
      <characteristic type="{xml_escape(cert_store_scope)}">
        <characteristic type="{xml_escape(issued_cert.thumbprint_sha1)}">
          <parm name="EncodedCertificate" value="{xml_escape(issued_cert.der_b64)}" />
        </characteristic>
        <characteristic type="PrivateKeyContainer"/>
      </characteristic>
      <characteristic type="WSTEP">
        <characteristic type="Renew">
          <parm name="ROBOSupport" value="true" datatype="boolean"/>
          <parm name="RenewPeriod" value="60" datatype="integer"/>
          <parm name="RetryInterval" value="4" datatype="integer"/>
        </characteristic>
      </characteristic>
    </characteristic>
  </characteristic>
  <characteristic type="APPLICATION">
    <parm name="APPID" value="w7"/>
    <parm name="PROVIDER-ID" value="{xml_escape(config.provider_id)}"/>
    <parm name="NAME" value="{xml_escape(config.provider_name)}"/>
    <parm name="ADDR" value="{xml_escape(config.syncml_url)}"/>
    <parm name="CONNRETRYFREQ" value="6" />
    <parm name="INITIALBACKOFFTIME" value="30000" />
    <parm name="MAXBACKOFFTIME" value="120000" />
    <parm name="BACKCOMPATRETRYDISABLED" />
    <parm name="DEFAULTENCODING" value="{xml_escape(config.default_encoding)}" />
    <parm name="SSLCLIENTCERTSEARCHCRITERIA" value="{xml_escape(cert_search)}"/>
    <characteristic type="APPAUTH">
      <parm name="AAUTHLEVEL" value="CLIENT"/>
      <parm name="AAUTHTYPE" value="DIGEST"/>
      <parm name="AAUTHSECRET" value="{xml_escape(client_secret)}"/>
      <parm name="AAUTHDATA" value="{xml_escape(server_nonce)}"/>
    </characteristic>
    <characteristic type="APPAUTH">
      <parm name="AAUTHLEVEL" value="APPSRV"/>
      <parm name="AAUTHTYPE" value="BASIC"/>
      <parm name="AAUTHNAME" value="{xml_escape(config.provider_id)}"/>
      <parm name="AAUTHSECRET" value="{xml_escape(server_secret)}"/>
    </characteristic>
  </characteristic>
  <characteristic type="DMClient">
    <characteristic type="Provider">
      <characteristic type="{xml_escape(config.provider_id)}">
        <parm name="UPN" value="{xml_escape(email)}" datatype="string" />
        <parm name="EntDMID" value="{xml_escape(device_id)}" datatype="string" />
        <characteristic type="Poll">
          <parm name="NumberOfFirstRetries" value="8" datatype="integer" />
          <parm name="IntervalForFirstSetOfRetries" value="15" datatype="integer" />
          <parm name="NumberOfSecondRetries" value="5" datatype="integer" />
          <parm name="IntervalForSecondSetOfRetries" value="3" datatype="integer" />
          <parm name="NumberOfRemainingScheduledRetries" value="0" datatype="integer" />
          <parm name="IntervalForRemainingScheduledRetries" value="1440" datatype="integer" />
          <parm name="PollOnLogin" value="true" datatype="boolean" />
        </characteristic>
        <parm name="EntDeviceName" value="{xml_escape(device_id)}" datatype="string" />
        <parm name="RequireMessageSigning" value="false" datatype="boolean" />
      </characteristic>
    </characteristic>
  </characteristic>
</wap-provisioningdoc>"""
