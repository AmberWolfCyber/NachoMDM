from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import quote, urlencode
from xml.etree import ElementTree as ET
import re
import uuid

from .xmlutil import attr_local, first_local, iter_local, parse_xml, text_of, xml_escape


SOAP_NS = "http://www.w3.org/2003/05/soap-envelope"
ADDR_NS = "http://www.w3.org/2005/08/addressing"
ENROLL_NS = "http://schemas.microsoft.com/windows/management/2012/01/enrollment"
XCEP_NS = "http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy"
WST_NS = "http://docs.oasis-open.org/ws-sx/ws-trust/200512"
WSSE_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"

ACTION_DISCOVER = "http://schemas.microsoft.com/windows/management/2012/01/enrollment/IDiscoveryService/Discover"
ACTION_DISCOVER_RESPONSE = ACTION_DISCOVER + "Response"
ACTION_GET_POLICIES = "http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPolicies"
ACTION_GET_POLICIES_RESPONSE = ACTION_GET_POLICIES + "Response"
ACTION_WSTEP_RST = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep"
ACTION_WSTEP_RSTRC = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RSTRC/wstep"


@dataclass(slots=True)
class ParsedSoap:
    root: ET.Element
    action: str = ""
    message_id: str = ""
    username: str = ""
    password: str = ""
    binary_tokens: list[tuple[str, str]] = field(default_factory=list)
    additional_context: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class DiscoveryRequest:
    email: str = ""
    request_version: str = "1.0"
    device_type: str = ""
    application_version: str = ""
    os_edition: str = ""
    auth_policies: list[str] = field(default_factory=list)


def parse_soap(body: bytes, header_action: str = "") -> ParsedSoap:
    root = parse_xml(body)
    parsed = ParsedSoap(root=root)
    parsed.action = _clean_action(header_action) or text_of(root, "Action")
    parsed.message_id = text_of(root, "MessageID")

    username = first_local(root, "Username")
    password = first_local(root, "Password")
    parsed.username = username.text.strip() if username is not None and username.text else ""
    parsed.password = password.text if password is not None and password.text else ""

    for token in iter_local(root, "BinarySecurityToken"):
        value_type = attr_local(token, "ValueType")
        parsed.binary_tokens.append((value_type, token.text.strip() if token.text else ""))

    for item in iter_local(root, "ContextItem"):
        name = attr_local(item, "Name")
        value = text_of(item, "Value")
        if name:
            parsed.additional_context[name] = value

    return parsed


def parse_discovery_request(parsed: ParsedSoap) -> DiscoveryRequest:
    request = DiscoveryRequest(
        email=text_of(parsed.root, "EmailAddress"),
        request_version=text_of(parsed.root, "RequestVersion", "1.0"),
        device_type=text_of(parsed.root, "DeviceType"),
        application_version=text_of(parsed.root, "ApplicationVersion"),
        os_edition=text_of(parsed.root, "OSEdition"),
    )
    request.auth_policies = [
        element.text.strip()
        for element in iter_local(parsed.root, "AuthPolicy")
        if element.text and element.text.strip()
    ]
    return request


def extract_pkcs10_token(parsed: ParsedSoap) -> str:
    for value_type, token in parsed.binary_tokens:
        if "PKCS10" in value_type.upper():
            return token
    if parsed.binary_tokens:
        return parsed.binary_tokens[-1][1]
    raise ValueError("No BinarySecurityToken containing a PKCS#10 request was found")


def build_discover_response(config, request: DiscoveryRequest, relates_to: str = "") -> str:
    auth_policy = choose_auth_policy(config.auth_policy, request.auth_policies)
    enrollment_version = choose_enrollment_version(config.enrollment_version, request.request_version)
    auth_service = ""
    if auth_policy == "Federated":
        auth_url = _authentication_service_url(config, request)
        auth_service = (
            "        <AuthenticationServiceUrl>"
            f"{xml_escape(auth_url)}</AuthenticationServiceUrl>\n"
        )

    body = f"""
    <DiscoverResponse xmlns="{ENROLL_NS}">
      <DiscoverResult>
        <AuthPolicy>{xml_escape(auth_policy)}</AuthPolicy>
        <EnrollmentVersion>{xml_escape(enrollment_version)}</EnrollmentVersion>
        <EnrollmentPolicyServiceUrl>{xml_escape(config.enrollment_policy_service_url)}</EnrollmentPolicyServiceUrl>
        <EnrollmentServiceUrl>{xml_escape(config.enrollment_service_url)}</EnrollmentServiceUrl>
{auth_service}      </DiscoverResult>
    </DiscoverResponse>"""
    return soap_envelope(ACTION_DISCOVER_RESPONSE, body, relates_to)


def build_xcep_response(relates_to: str = "", enrollment_version: str = "5.0") -> str:
    attestation = ""
    if _version_float(enrollment_version) >= 5.0:
        attestation = """
                  <AttestationFailureBehavior>RetryOnError</AttestationFailureBehavior>
                  <OperationTimeout>100</OperationTimeout>"""
    body = f"""
    <GetPoliciesResponse xmlns="{XCEP_NS}" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
      <response>
        <policyID />
        <policyFriendlyName xsi:nil="true"/>
        <nextUpdateHours xsi:nil="true"/>
        <policiesNotChanged xsi:nil="true"/>
        <policies>
          <policy>
            <policyOIDReference>0</policyOIDReference>
            <cAs xsi:nil="true"/>
            <attributes>
              <commonName>MDM Client Authentication</commonName>
              <policySchema>3</policySchema>
              <certificateValidity>
                <validityPeriodSeconds>63072000</validityPeriodSeconds>
                <renewalPeriodSeconds>3628800</renewalPeriodSeconds>
              </certificateValidity>
              <permission>
                <enroll>true</enroll>
                <autoEnroll>false</autoEnroll>
              </permission>
              <privateKeyAttributes>
                <minimalKeyLength>2048</minimalKeyLength>
                <keySpec xsi:nil="true"/>
                <keyUsageProperty xsi:nil="true"/>
                <permissions xsi:nil="true"/>
                <algorithmOIDReference xsi:nil="true"/>{attestation}
                <cryptoProviders>
                  <provider>Microsoft Platform Crypto Provider</provider>
                  <provider>Microsoft Software Key Storage Provider</provider>
                </cryptoProviders>
              </privateKeyAttributes>
              <revision>
                <majorRevision>1</majorRevision>
                <minorRevision>0</minorRevision>
              </revision>
              <supersededPolicies xsi:nil="true"/>
              <privateKeyFlags xsi:nil="true"/>
              <subjectNameFlags xsi:nil="true"/>
              <enrollmentFlags xsi:nil="true"/>
              <generalFlags xsi:nil="true"/>
              <hashAlgorithmOIDReference>0</hashAlgorithmOIDReference>
              <rARequirements xsi:nil="true"/>
              <keyArchivalAttributes xsi:nil="true"/>
              <extensions xsi:nil="true"/>
            </attributes>
          </policy>
        </policies>
      </response>
      <cAs xsi:nil="true"/>
      <oIDs>
        <oID>
          <value>2.16.840.1.101.3.4.2.1</value>
          <group>4</group>
          <oIDReferenceID>0</oIDReferenceID>
          <defaultName>szOID_NIST_sha256</defaultName>
        </oID>
      </oIDs>
    </GetPoliciesResponse>"""
    return soap_envelope(ACTION_GET_POLICIES_RESPONSE, body, relates_to)


def build_wstep_response(provisioning_doc_b64: str, relates_to: str = "") -> str:
    body = f"""
    <wst:RequestSecurityTokenResponseCollection xmlns:wst="{WST_NS}" xmlns:wsse="{WSSE_NS}">
      <wst:RequestSecurityTokenResponse>
        <wst:TokenType>http://schemas.microsoft.com/5.0.0.0/ConfigurationManager/Enrollment/DeviceEnrollmentToken</wst:TokenType>
        <wst:RequestedSecurityToken>
          <wsse:BinarySecurityToken
              ValueType="http://schemas.microsoft.com/5.0.0.0/ConfigurationManager/Enrollment/DeviceEnrollmentProvisionDoc"
              EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary">{provisioning_doc_b64}</wsse:BinarySecurityToken>
        </wst:RequestedSecurityToken>
      </wst:RequestSecurityTokenResponse>
    </wst:RequestSecurityTokenResponseCollection>"""
    return soap_envelope(ACTION_WSTEP_RSTRC, body, relates_to)


def build_fault(reason: str, relates_to: str = "") -> str:
    body = f"""
    <s:Fault>
      <s:Code><s:Value>s:Sender</s:Value></s:Code>
      <s:Reason><s:Text xml:lang="en-US">{xml_escape(reason)}</s:Text></s:Reason>
    </s:Fault>"""
    return soap_envelope("", body, relates_to)


def soap_envelope(action: str, body_xml: str, relates_to: str = "") -> str:
    relates = f"<a:RelatesTo>{xml_escape(relates_to)}</a:RelatesTo>" if relates_to else ""
    action_xml = (
        f"<a:Action s:mustUnderstand=\"1\">{xml_escape(action)}</a:Action>"
        if action
        else ""
    )
    return f"""<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="{SOAP_NS}" xmlns:a="{ADDR_NS}">
  <s:Header>
    {action_xml}
    <a:MessageID>urn:uuid:{uuid.uuid4()}</a:MessageID>
    {relates}
  </s:Header>
  <s:Body>{body_xml}
  </s:Body>
</s:Envelope>"""


def choose_auth_policy(configured: str, offered: list[str]) -> str:
    configured = configured or "OnPremise"
    if not offered or configured in offered:
        return configured
    for candidate in ("OnPremise", "Federated", "Certificate"):
        if candidate in offered:
            return candidate
    return configured


def choose_enrollment_version(configured: str, requested: str) -> str:
    configured_value = _version_float(configured)
    requested_value = _version_float(requested)
    if requested_value <= 0:
        return configured
    chosen = min(configured_value, requested_value)
    if chosen <= 0:
        return configured
    return f"{chosen:.1f}"


def _authentication_service_url(config, request: DiscoveryRequest) -> str:
    url = config.authentication_service_url
    if not getattr(config, "federated_auth_stub", False):
        return url

    params: dict[str, str] = {}
    if request.device_type or request.application_version:
        params["deviceinfo"] = f"{request.device_type}__{request.application_version}"
    params["profile_id"] = "lab"
    if not params:
        return url
    separator = "&" if "?" in url else "?"
    return url + separator + urlencode(params)


def _version_float(value: str) -> float:
    match = re.search(r"\d+(?:\.\d+)?", value or "")
    return float(match.group(0)) if match else 0.0


def _clean_action(value: str) -> str:
    value = value.strip().strip('"')
    if not value:
        return ""
    if value.lower().startswith("application/soap+xml"):
        if "action=" not in value.lower():
            return ""
        match = re.search(r"action=\"?([^\";]+)", value)
        if match:
            return match.group(1)
    return value


def url_encode_subject(subject: str) -> str:
    return quote(subject, safe="")
