import datetime
from io import BytesIO
import json
import os
import re
import requests
import getpass
import subprocess
from lxml import etree
import urllib3
from requests.auth import HTTPBasicAuth
import sys
import csv

# === CONFIG ===
# disable insecure requests warning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def initialise_logs():
    # Create csv for pages
    startTimestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    page_log = f"page_log_{startTimestamp}.csv"
    skipped_macro_log = f"skipped_macro_log_{startTimestamp}.csv"
    unresolved_include_log = f"unresolved_include_log_{startTimestamp}.csv"
    approval_log = f"approval_log_{startTimestamp}.csv"

    LOG_DEFS = {
        page_log : ['timestamp', 'page_id', 'Successfully_Updated', 'message', 'comment_message'],
        skipped_macro_log : ['timestamp', 'uml_id', 'page_id', 'error_message'],
        unresolved_include_log : ['timestamp', 'uml_id', 'page_id'],
        approval_log : ['timestamp', 'page_id']
    }

    for filename, headers in LOG_DEFS.items():
        with open(filename, mode='w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(headers)
    
    return page_log, skipped_macro_log, unresolved_include_log, approval_log


def append_to_log(filename, data):
    datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = [datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")] + data
    with open(filename, mode='a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(log_entry)

def get_credentials():
    username = input("Enter your Confluence username: ")
    password = getpass.getpass("Enter your Confluence password: ")
    # password = input("Enter your Confluence password: ") # for api key
    return username, password

def get_timestamp():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def check_approvals(page_id, apiAuth):
    approvalsURL = f"https://confluence.service.anz/rest/cw/1/content/{page_id}/status"

    response = requests.get(approvalsURL, auth=apiAuth, verify = False)
    return response.status_code == 200


def extract_plantumlrender_code(node):
    # check for pre tag and process
    pre = node.find(".//pre")
    if pre:
        text = pre.text or ""
        for elem in pre:
            if elem.tag == 'br':
                text += "\n"
                if elem.tail:
                    text += elem.tail
        return text.strip()

    # if no pre tag, fall back to p tags
    lines = []
    for p in node.findall(".//p"):
        if p.text:
            lines.append(p.text)
        for child in p:
            if child.tail:
                lines.append(child.tail)
    return "\n".join(lines).strip() if lines else None

def render_plantuml_to_image(source_code: str, server_url: str) -> BytesIO:
    """
    Sends PlantUML source code to a PlantUML server for rendering.

    Args:
        source_code (str): The PlantUML source code to render.
        server_url (str): The URL of the PlantUML server (e.g., "http://localhost:8080").

    Returns:
        BytesIO: A BytesIO stream containing the rendered UML image, or None if rendering fails.
    """
    try:
        # Send the source code to the PlantUML server
        response = requests.post(
            f"{server_url}/png",
            data=source_code.encode('utf-8'),
            headers={"Content-Type": "text/plain"}
        )

        # Check if the request was successful
        if response.status_code == 200:
            return BytesIO(response.content)
        else:
            print(f"PlantUML server error: {response.status_code}")
            return None
    except Exception as e:
        print(f"Error connecting to PlantUML server: {e}")
        return None

def process_includes(source_code: str, include_dir: str) -> str | None:
    updated_lines = []
    lines = source_code.splitlines()

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("!include"):
            # Match everything after !include and optional whitespace
            match = re.match(r"!include\s+(.*)", stripped)
            if match:
                include_path = match.group(1)
                # Try to split on caret and extract filename
                if '^' in include_path:
                    filename = include_path.split('^')[-1]
                else:
                    filename = os.path.basename(include_path)

                container_path = f"/app/include_files/{filename}"

                result = subprocess.run(
                    ["docker", "exec", "plantuml_server", "test", "-f", container_path],
                    capture_output=True
                )

                if result.returncode == 0:
                    updated_line = f"!include {container_path}"
                    updated_lines.append(updated_line)
                else:
                    print(f"Include file not found: {container_path}")
                    return False, filename  # Exit early
            else:
                updated_lines.append(line)
        else:
            updated_lines.append(line)

    return True, "\n".join(updated_lines)

def process_macro(macro, server_url, uml_id, page_id, skipped_macro_log, unresolved_include_log):
    # Determine whether the macro is plantuml or plantumlrender
    macro_type = macro.attrib.get('{http://atlassian.com/content}name')

    if macro_type == "plantuml":
        # find node with plain-text-body id
        node = macro.find('.//ac:plain-text-body', namespaces={'ac': 'http://atlassian.com/content'})
        # check if something wrong with node
        if node is None or node.text is None:
            append_to_log(skipped_macro_log, [uml_id, page_id, "plantuml macro has incorrect syntax"])
            return None, None
        # store source code
        source_code = node.text

    elif macro_type == "plantumlrender":
        # find node with rich-text-body id
        node = macro.find('.//ac:rich-text-body', namespaces={'ac': 'http://atlassian.com/content'})
        # get the source code from the node
        source_code = extract_plantumlrender_code(node)
        # handle bad node
        if not source_code:
            append_to_log(skipped_macro_log, [uml_id, page_id, "plantumlrender macro has incorrect syntax"])
            return None, None
        
    else:
        # if the macro's type is not plantUML raise an error
        append_to_log(skipped_macro_log, [uml_id, page_id, f"wrong macro type: {macro_type}"])
        return None, None
    
    # processed is boolean on whether the includes were processed correctly
    # text is unresolved file if not processed and code to render if processed
    processed, text = process_includes(source_code, "/app/include_files")
    if not processed:
        append_to_log(unresolved_include_log, [uml_id, page_id, f"Include files not resolved: {text}"])
        return None, source_code
    
    # if includes were correctly processed, render the code
    render_code = text
    # Render source code into image
    image_data = render_plantuml_to_image(render_code, server_url)

    # if the rendering fails, log and return accordingly
    if not image_data:
        append_to_log(skipped_macro_log, [uml_id, page_id, "Image failed to render"])
        return None, source_code

    # Return tuple to be used for updating the Confluence page
    return image_data, source_code

def start_plantuml_container():
    includes_path = os.path.join(os.getcwd(), "include_files")
    try:
        subprocess.run([
            "docker", "run", "-d",
            "--name", "plantuml_server", 
            "-p", "8080:8080",
            "-v", f"{includes_path}:/app/include_files",
            "-e", "PLANTUML_SECURITY_PROFILE=UNSECURE",
            "plantuml/plantuml-server"
        ], check=True)
        print("PlantUML Docker container started.")
    except subprocess.CalledProcessError as e:
        print("Failed to start PlantUML container:", e)

def add_comment_to_page(page_id, apiAuth, page_log):
    url = f"https://confluence.service.anz/rest/api/content/{page_id}/child/comment"

    data = {
        "type": "comment",
        "container": {
            "id": page_id,
            "type": "page"
        },
        "body": {
            "storage": {
                "value": "This page has been modified as, following migration to the Confluence Cloud, the PlantUML macro will no longer be available. To resolve this we have deleted the macro and replaced it with a screenshot of the latest PlantUML image. The PlantUML code has been added beneath the screenshot in the Expand Macro. Please contact atlassiancloud@anz.com if you have any questions",
                "representation": "storage"
            }
        }
    }
    
    print("the data is ",data)

    response = requests.post(
        url,
        headers={"Content-Type": "application/json"},
        data=json.dumps(data),
        auth=apiAuth,
        verify=False
    )


    if response.status_code == 200 or response.status_code == 201:
        return "Comment added successfully"
    else:
        print(f"Failed to add comment: {response.status_code} - {response.text}")
        return f"Failed to add comment: {response.status_code} - {response.text}"
    
def runScript(fileName, server_url="http://localhost:8080"):
    username, password = get_credentials()
    apiAuth = HTTPBasicAuth(username, password)

    # Create logs
    page_log, skipped_macro_log, unresolved_include_log, approval_log = initialise_logs()

    # List of page IDs to check
    with open(fileName, "r") as file:
        page_ids = [line.strip() for line in file if line.strip()]

    # start plantuml docker container
    start_plantuml_container()

    # namespace declaration for image
    AC_NS = "http://atlassian.com/content" # namespace for atlassian content
    RI_NS = "http://atlassian.com/resource/identifier" # namespace for atlassian resource identifier
    NSMAP = {'ac': AC_NS, 'ri': RI_NS}

    for page_id in page_ids:
        counter = 1

        print(f"Processing page {page_id}...")
        
        # Check for approvals
        if check_approvals(page_id, apiAuth):
            append_to_log(approval_log, [page_id])
            continue # do not go through rest of process

        # no approvals on page so keep going
        # save url for get call
        # Atlassian Confluence REST api endpoints
        getURL = f"https://confluence.service.anz/rest/api/content/{page_id}?expand=body.storage,version"
        attachURL = f"https://confluence.service.anz/rest/api/content/{page_id}/child/attachment"
        updateURL = f"https://confluence.service.anz/rest/api/content/{page_id}"

        # response includes the status code, text etc.
        # TODO: change from username and password to API key
        response = requests.get(getURL, auth=apiAuth, verify = False)

        # check if get request worked correctly
        if response.status_code != 200:
            if response.status_code == 403:
                append_to_log(page_log, [page_id, "No", "403: access not granted"])
            elif response.status_code == 404:
                append_to_log(page_log, [page_id, "No", "404: page does not exist or access not granted"])
            elif response.status_code == 502:
                append_to_log(page_log, [page_id, "No", "502: bad gateway, likely proxy error"])
            else:
                append_to_log(page_log, [page_id, "No", f"{response.status_code}: page not processed"])
            continue # do not go through rest of process
        
        
        data = response.json()
        current_body = data["body"]["storage"]["value"]
        title = data["title"]
        current_version = data["version"]["number"]

        # Creates an etree parser
        parser = etree.XMLParser(recover=True)

        # Turn our current body into an xml tree so we can process it
        tree = etree.fromstring(f"<root xmlns:ac='http://atlassian.com/content'>{current_body}</root>", parser=parser)

        # print(etree.tostring(tree, pretty_print=True).decode()) # Just to test

        # extracts all plantUML macro nodes
        plantMacros = tree.xpath(
            '//ac:structured-macro[@ac:name="plantuml" or @ac:name="plantumlrender"]', namespaces={'ac': 'http://atlassian.com/content'}
        )

        for macro in plantMacros:
            # create id for uml and increment counter
            uml_id = f"puml_{page_id}_{str(counter)}"
            counter += 1

            # get the image and source code
            image_data, source_code = process_macro(macro, server_url, uml_id, page_id, skipped_macro_log, unresolved_include_log)
            
            # if the macro could not be processed, we want to continue
            # already logged in the process_macro function
            if not image_data:
                continue

            # POST to attach the image to the confluence page
            # TODO: change from username and password to API key
            requests.post(attachURL, 
                          auth=apiAuth,
                          headers = {"X-Atlassian-Token": "no-check"}, 
                          files={'file':(f"{uml_id}.png", image_data.getvalue(), 'image/png')}, 
                          verify=False
                          )
        
            # Create tree node for uml image
            image_elem = etree.Element("{%s}image" % AC_NS, nsmap=NSMAP) # image
            attachment_elem = etree.SubElement(image_elem, "{%s}attachment" % RI_NS) # tag to attach image 
            attachment_elem.set("{%s}filename" % RI_NS, f"{uml_id}.png")

            # Create the hidden macro (expand)
            hidden_macro_elem = etree.Element("{%s}structured-macro" % AC_NS, nsmap=NSMAP)
            hidden_macro_elem.set("{%s}name" % AC_NS, "expand")

            # Add the title parameter to customize the expand button
            title_elem = etree.SubElement(hidden_macro_elem, "{%s}parameter" % AC_NS)
            title_elem.set("{%s}name" % AC_NS, "title")
            title_elem.text = "Show Source Code"  # Customize this title as needed

            # Add the rich-text-body to hold the content
            rich_body_elem = etree.SubElement(hidden_macro_elem, "{%s}rich-text-body" % AC_NS)

            # Add a pre tag to show the source code as preformatted text
            pre_elem = etree.SubElement(rich_body_elem, "pre")
            pre_elem.text = source_code  # no CDATA needed; <pre> will preserve formatting

            # get current location of macro for replacement
            parent = macro.getparent()
            macro_index = parent.index(macro)
            parent.remove(macro)

            # Insert image and hidden macro at the same spot
            parent.insert(macro_index, image_elem)
            parent.insert(macro_index+1, hidden_macro_elem)

            # print(etree.tostring(tree, pretty_print=True).decode()) # Just to test
            
        # convert etree to string to send to confluence api
        new_body = etree.tostring(tree, encoding="unicode")

        # set header and payload for put request
        headers = {"Content-Type": "application/json"}
        payload = {
            "id": page_id,
            "type": "page",
            "title": title,
            "version": {"number": current_version + 1},
            "body": {
                "storage": {
                    "value": new_body,
                    "representation": "storage"
                }
            }
        }
        
        # TODO: change from username and password to API key
        update_response = requests.put(updateURL, headers=headers, json=payload, auth=apiAuth, verify=False)

        if update_response.status_code == 200:
            comment_message = add_comment_to_page(page_id, apiAuth, page_log)
            append_to_log(page_log, [page_id, "Yes", "Page updated successfully", comment_message])
            
        else:
            append_to_log(page_log, [page_id, "No", f"Failed to update page: {update_response.status_code}", "N/A"])
    
    # Stop and remove the container
    subprocess.run(["docker", "stop", "plantuml_server"], check=True)
    subprocess.run(["docker", "rm", "plantuml_server"], check=True)
            
    print("Script finished")


if len(sys.argv) != 2:
    print("Usage: python script.py <filename>")
    sys.exit(1)

filename = sys.argv[1]

runScript(filename)
