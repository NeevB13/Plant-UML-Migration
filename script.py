import datetime
from io import BytesIO
import os
import requests
import getpass
import subprocess
from lxml import etree
from pathlib import Path
import urllib3
from requests.auth import HTTPBasicAuth

# === CONFIG ===
# disable insecure requests warning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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

def process_macro(macro, server_url, uml_id, page_id, skipped_log_filename):
    # Determine whether the macro is plantuml or plantumlrender
    macro_type = macro.attrib.get('{http://atlassian.com/content}name')

    if macro_type == "plantuml":
        # find node with plain-text-body id
        node = macro.find('.//ac:plain-text-body', namespaces={'ac': 'http://atlassian.com/content'})
        # check if something wrong with node
        if node is None or node.text is None:
            timestamp = get_timestamp()
            with open(skipped_log_filename, "a") as failed_log:
                failed_log.write(f"{timestamp}: plantuml macro {uml_id} on page https://confluence.service.anz/pages/viewpage.action?pageId={page_id} has incorrect syntax.\n")
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
            timestamp = get_timestamp()
            with open(skipped_log_filename, "a") as failed_log:
                failed_log.write(f"{timestamp}: plantuml macro {uml_id} on page https://confluence.service.anz/pages/viewpage.action?pageId={page_id} has incorrect syntax.\n")
            return None, None
        
    else:
        # if the macro's type is not plantUML raise an error
        raise ValueError(f"Wrong macro: {macro_type}")
    
    # Render source code into image
    image_data = render_plantuml_to_image(source_code, server_url)

    # if the rendering fails, log and return accordingly
    if not image_data:
        timestamp = get_timestamp()
        with open(skipped_log_filename, "a") as failed_log:
            failed_log.write(f"{timestamp}: Macro {uml_id} on page https://confluence.service.anz/pages/viewpage.action?pageId={page_id} failed to render.\n")
        return None, source_code

    # Return tuple to be used for updating the Confluence page
    return image_data, source_code
    
def runScript(fileName, server_url="http://localhost:8080"):
    # Create logs
    startTimestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    skipped_log_filename = f"skipped_log_{startTimestamp}.txt"
    processed_log_filename = f"processed_pages_{startTimestamp}.txt"

    # List of page IDs to check
    with open(fileName, "r") as file:
        page_ids = [line.strip() for line in file if line.strip()]


    username, password = get_credentials()
    apiAuth = HTTPBasicAuth(username, password)

    # namespace declaration for image
    AC_NS = "http://atlassian.com/content" # namespace for atlassian content
    RI_NS = "http://atlassian.com/resource/identifier" # namespace for atlassian resource identifier
    NSMAP = {'ac': AC_NS, 'ri': RI_NS}

    for page_id in page_ids:
        counter = 1

        print(f"Processing page {page_id}...")
        
        # Check for approvals
        if check_approvals(page_id, apiAuth):
            timestamp = get_timestamp()
            with open(skipped_log_filename, "a") as failed_log:
                # if there are approvals on the page, we want to add it to the failed log and keep going
                failed_log.write(f"{timestamp}: Page {page_id} not processed as it has approvals\n")
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
            # if not 200, we have an issue so page cannot be processed
            timestamp = get_timestamp()
            with open(skipped_log_filename, "a") as failed_log:
                if response.status_code == 403:
                    failed_log.write(f"{timestamp}: Page https://confluence.service.anz/pages/viewpage.action?pageId={page_id} not processed as access not granted\n")
                elif response.status_code == 404:
                    failed_log.write(f"{timestamp}: Page https://confluence.service.anz/pages/viewpage.action?pageId={page_id} not processed as it does not exist or access is not granted\n")
                elif response.status_code == 502:
                    failed_log.write(f"{timestamp}: Page https://confluence.service.anz/pages/viewpage.action?pageId={page_id} bad gateway, likely proxy error\n")
                else:
                    failed_log.write(f"{timestamp}: Page https://confluence.service.anz/pages/viewpage.action?pageId={page_id} not processed with error code {response.status_code}\n")
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
            image_data, source_code = process_macro(macro, server_url, uml_id, page_id, skipped_log_filename)
            
            # if the macro could not be processed, we want to continue
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
            timestamp = get_timestamp()
            with open(processed_log_filename, "a") as processed_pages:
                processed_pages.write(f"{timestamp}: Page https://confluence.service.anz/pages/viewpage.action?pageId={page_id} updated successfully\n")
        else:
            with open(skipped_log_filename, "a") as failed_log:
                failed_log.write(f"{timestamp}: Page https://confluence.service.anz/pages/viewpage.action?pageId={page_id} not updated successfully\n")

    print("Script finished")

runScript("page_ids.txt")
