from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import quote
from xml.etree import ElementTree as ET

from .xmlutil import first_local, iter_local, local_name, parse_xml, text_of, xml_escape


@dataclass(slots=True)
class SyncCommand:
    name: str
    cmd_id: str
    data: str = ""
    loc_uri: str = ""


@dataclass(slots=True)
class SyncRequest:
    session_id: str = "1"
    msg_id: str = "1"
    source: str = ""
    target: str = ""
    commands: list[SyncCommand] = field(default_factory=list)
    alerts: list[SyncCommand] = field(default_factory=list)
    results: list[SyncCommand] = field(default_factory=list)


def parse_syncml(body: bytes) -> SyncRequest:
    root = parse_xml(body)
    header = first_local(root, "SyncHdr") or root
    request = SyncRequest(
        session_id=text_of(header, "SessionID", "1"),
        msg_id=text_of(header, "MsgID", "1"),
        source=_loc_uri(first_local(header, "Source")),
        target=_loc_uri(first_local(header, "Target")),
    )
    body_el = first_local(root, "SyncBody")
    if body_el is None:
        return request

    for child in list(body_el):
        name = local_name(child.tag)
        if name == "Final":
            continue
        cmd = SyncCommand(
            name=name,
            cmd_id=text_of(child, "CmdID"),
            data=text_of(child, "Data"),
            loc_uri=_first_item_uri(child),
        )
        request.commands.append(cmd)
        if name == "Alert":
            request.alerts.append(cmd)
        elif name == "Results":
            request.results.append(cmd)
    return request


def build_syncml_response(config, request: SyncRequest, enrollment=None) -> tuple[str, bool]:
    cmd_id = 1
    status_blocks: list[str] = []
    status_blocks.append(_status(cmd_id, request.msg_id, "0", "SyncHdr", "200"))
    cmd_id += 1

    for command in request.commands:
        if command.cmd_id:
            status_blocks.append(_status(cmd_id, request.msg_id, command.cmd_id, command.name, "200"))
            cmd_id += 1

    command_blocks: list[str] = []
    command_blocks.append(_inventory_get(cmd_id))
    cmd_id += 1

    agent_command_sent = False
    if enrollment and config.agent.enabled:
        if enrollment.agent_state == "pending":
            add_xml, exec_xml = _agent_install_commands(config, cmd_id)
            command_blocks.append(add_xml)
            command_blocks.append(exec_xml)
            cmd_id += 2
            agent_command_sent = True
        elif enrollment.agent_state in {"sent", "installing"}:
            command_blocks.append(_agent_status_get(config, cmd_id))
            cmd_id += 1

    response = f"""<?xml version="1.0" encoding="utf-8"?>
<SyncML xmlns="SYNCML:SYNCML1.2">
  <SyncHdr>
    <VerDTD>1.2</VerDTD>
    <VerProto>DM/1.2</VerProto>
    <SessionID>{xml_escape(request.session_id)}</SessionID>
    <MsgID>{_server_msg_id(request.msg_id)}</MsgID>
    <Target><LocURI>{xml_escape(request.source)}</LocURI></Target>
    <Source><LocURI>{xml_escape(request.target or config.syncml_url)}</LocURI></Source>
  </SyncHdr>
  <SyncBody>
{''.join(status_blocks)}
{''.join(command_blocks)}
    <Final/>
  </SyncBody>
</SyncML>"""
    return response, agent_command_sent


def classify_agent_alerts(request: SyncRequest, product_id: str) -> str | None:
    product_id_plain = product_id.strip("{}").lower()
    for alert in request.alerts:
        if product_id_plain in alert.loc_uri.lower() and "DownloadInstall" in alert.loc_uri:
            if alert.data in {"0", "200", "70"}:
                return "completed"
            return "failed"
    for result in request.results:
        if product_id_plain in result.loc_uri.lower() and result.data == "70":
            return "completed"
    return None


def _status(cmd_id: int, msg_ref: str, cmd_ref: str, cmd: str, data: str) -> str:
    return f"""    <Status>
      <CmdID>{cmd_id}</CmdID>
      <MsgRef>{xml_escape(msg_ref)}</MsgRef>
      <CmdRef>{xml_escape(cmd_ref)}</CmdRef>
      <Cmd>{xml_escape(cmd)}</Cmd>
      <Data>{xml_escape(data)}</Data>
    </Status>
"""


def _inventory_get(cmd_id: int) -> str:
    paths = [
        "./DevInfo/DevId",
        "./DevInfo/Man",
        "./DevInfo/Mod",
        "./DevDetail/SwV",
        "./DevDetail/Ext/Microsoft/OSPlatform",
    ]
    items = "\n".join(
        f"      <Item><Target><LocURI>{xml_escape(path)}</LocURI></Target></Item>" for path in paths
    )
    return f"""    <Get>
      <CmdID>{cmd_id}</CmdID>
{items}
    </Get>
"""


def _agent_install_commands(config, cmd_id: int) -> tuple[str, str]:
    loc_uri = _agent_download_install_uri(config)
    add_xml = f"""    <Add>
      <CmdID>{cmd_id}</CmdID>
      <Item>
        <Target><LocURI>{xml_escape(loc_uri)}</LocURI></Target>
      </Item>
    </Add>
"""
    exec_xml = f"""    <Exec>
      <CmdID>{cmd_id + 1}</CmdID>
      <Item>
        <Target><LocURI>{xml_escape(loc_uri)}</LocURI></Target>
        <Meta>
          <Format xmlns="syncml:metinf">xml</Format>
          <Type xmlns="syncml:metinf">text/plain</Type>
        </Meta>
        <Data>
          <MsiInstallJob id="{xml_escape(config.agent.job_id)}">
            <Product Version="{xml_escape(config.agent.version)}">
              <Download>
                <ContentURLList>
                  <ContentURL>{xml_escape(config.agent.url)}</ContentURL>
                </ContentURLList>
              </Download>
              <Validation>
                <FileHash>{xml_escape(config.agent.sha256.upper())}</FileHash>
              </Validation>
              <Enforcement>
                <CommandLine>{xml_escape(config.agent.command_line)}</CommandLine>
                <TimeOut>{int(config.agent.timeout_minutes)}</TimeOut>
                <RetryCount>{int(config.agent.retry_count)}</RetryCount>
                <RetryInterval>{int(config.agent.retry_interval_minutes)}</RetryInterval>
                <DownloadFromAad>{1 if config.agent.download_from_aad else 0}</DownloadFromAad>
              </Enforcement>
            </Product>
          </MsiInstallJob>
        </Data>
      </Item>
    </Exec>
"""
    return add_xml, exec_xml


def _agent_status_get(config, cmd_id: int) -> str:
    base = _agent_base_uri(config)
    paths = [
        f"{base}/Status",
        f"{base}/LastError",
        f"{base}/LastErrorDesc",
        f"{base}/Version",
    ]
    items = "\n".join(
        f"      <Item><Target><LocURI>{xml_escape(path)}</LocURI></Target></Item>" for path in paths
    )
    return f"""    <Get>
      <CmdID>{cmd_id}</CmdID>
{items}
    </Get>
"""


def _agent_base_uri(config) -> str:
    product_id = quote(config.agent.product_id, safe="")
    return f"./Device/Vendor/MSFT/EnterpriseDesktopAppManagement/MSI/{product_id}"


def _agent_download_install_uri(config) -> str:
    return _agent_base_uri(config) + "/DownloadInstall"


def _first_item_uri(element: ET.Element) -> str:
    item = first_local(element, "Item")
    if item is None:
        return ""
    target = first_local(item, "Target")
    source = first_local(item, "Source")
    return _loc_uri(target) or _loc_uri(source)


def _loc_uri(container: ET.Element | None) -> str:
    if container is None:
        return ""
    loc = first_local(container, "LocURI")
    return loc.text.strip() if loc is not None and loc.text else ""


def _server_msg_id(value: str) -> str:
    try:
        return str(max(1, int(value)))
    except ValueError:
        return "1"
