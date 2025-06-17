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
    """
    Initializes log files for tracking the script's progress and issues.

    Creates four CSV log files:
    - `page_log`: Logs the status of page updates.
    - `skipped_macro_log`: Logs macros that were skipped due to errors.
    - `unresolved_include_log`: Logs unresolved include files.
    - `approval_log`: Logs pages that were skipped due to having approvals.

    Returns:
        tuple: A tuple containing the filenames of the four log files.
    """
    # Create csv for pages
    startTimestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    page_log = f"page_log_{startTimestamp}.csv"
    skipped_macro_log = f"skipped_macro_log_{startTimestamp}.csv"
    unresolved_include_log = f"unresolved_include_log_{startTimestamp}.csv"
    approval_log = f"approval_log_{startTimestamp}.csv"

    LOG_DEFS = {
        page_log: ['timestamp', 'URL', 'page_id', 'Successfully_Updated', 'message', 'comment_message'],
        skipped_macro_log: ['timestamp', 'URL', 'uml_id', 'page_id', 'error_message'],
        unresolved_include_log: ['timestamp', 'URL', 'uml_id', 'page_id'],
        approval_log: ['timestamp', 'URL', 'page_id']
    }

    for filename, headers in LOG_DEFS.items():
        with open(filename, mode='w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(headers)

    return page_log, skipped_macro_log, unresolved_include_log, approval_log


def append_to_log(filename, data, page_id):
    """
    Appends a log entry to the specified log file.

    Args:
        filename (str): The name of the log file.
        data (list): A list of data to be written as a row in the log file.
    """
    timeNow = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    url = f"https://confluence.service.anz/pages/viewpage.action?pageId={page_id} "
    log_entry = [timeNow, url] + data
    with open(filename, mode='a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(log_entry)


def get_credentials():
    """
    Prompts the user to enter their Confluence username and password.

    Returns:
        tuple: A tuple containing the username and password.
    """
    username = input("Enter your Confluence username: ")
    password = getpass.getpass("Enter your Confluence password: ")
    # password = input("Enter your Confluence password: ") # for api key
    return username, password


def check_approvals(page_id, tree, apiAuth):
    """
    Checks if a Confluence page has approvals.

    Args:
        page_id (str): The ID of the Confluence page.
        tree (etree._Element): The XML tree of the page content.
        apiAuth (HTTPBasicAuth): The authentication object for API requests.

    Returns:
        bool: True if the page has approvals, False otherwise.
    """
    approvalsURL = f"https://confluence.service.anz/rest/cw/1/content/{page_id}/status"
    ns = {"ac": "http://atlassian.com/content"}

    response = requests.get(approvalsURL, auth=apiAuth, verify=False)
    if response.status_code == 200:
        return True

    return tree.xpath(".//ac:structured-macro[@ac:name='pageapproval']", namespaces=ns)


def extract_plantumlrender_code(node):
    """
    Extracts the PlantUML source code from a `plantumlrender` macro.

    Args:
        node (etree._Element): The XML node representing the macro.

    Returns:
        str: The extracted PlantUML source code, or None if extraction fails.
    """
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
            return None
    except Exception as e:
        return None


def process_includes(source_code: str, include_dir: str):
    """
    Processes `!include` statements in the PlantUML source code.

    Args:
        source_code (str): The PlantUML source code.
        include_dir (str): The directory containing include files.

    Returns:
        tuple: A tuple containing:
            - bool: True if all includes were resolved, False otherwise.
            - str: The updated source code or the unresolved file name.
    """
    updated_lines = []
    lines = source_code.splitlines()

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("!includeurl"):
            url = stripped[len("!includeurl"):].strip()
            return False, url  # Early exit with unresolved URL
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
                    return False, filename  # Exit early
            else:
                updated_lines.append(line)
        else:
            updated_lines.append(line)

    return True, "\n".join(updated_lines)


def process_macro(macro, server_url, uml_id, page_id, skipped_macro_log, unresolved_include_log):
    """
    Processes a PlantUML macro and renders it into an image.

    Args:
        macro (etree._Element): The XML node representing the macro.
        server_url (str): The URL of the PlantUML server.
        uml_id (str): A unique ID for the UML diagram.
        page_id (str): The ID of the Confluence page.
        skipped_macro_log (str): The log file for skipped macros.
        unresolved_include_log (str): The log file for unresolved includes.

    Returns:
        tuple: A tuple containing:
            - BytesIO: The rendered UML image, or None if rendering fails.
            - str: The original or processed source code.
    """
    # Determine whether the macro is plantuml or plantumlrender
    macro_type = macro.attrib.get('{http://atlassian.com/content}name')

    if macro_type == "plantuml":
        # find node with plain-text-body id
        node = macro.find('.//ac:plain-text-body', namespaces={'ac': 'http://atlassian.com/content'})
        # check if something wrong with node
        if node is None or node.text is None:
            append_to_log(skipped_macro_log, [uml_id, page_id, "plantuml macro has incorrect syntax"], page_id)
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
            append_to_log(skipped_macro_log, [uml_id, page_id, "plantumlrender macro has incorrect syntax"], page_id)
            return None, None

    else:
        # if the macro's type is not plantUML raise an error
        append_to_log(skipped_macro_log, [uml_id, page_id, f"wrong macro type: {macro_type}"], page_id)
        return None, None

    # processed is boolean on whether the includes were processed correctly
    # text is unresolved file if not processed and code to render if processed
    processed, text = process_includes(source_code, "/app/include_files")
    if not processed:
        append_to_log(unresolved_include_log, [uml_id, page_id, f"Include files not resolved: {text}"], page_id)
        return None, source_code

    # if includes were correctly processed, render the code
    render_code = text
    # Render source code into image
    image_data = render_plantuml_to_image(render_code, server_url)

    # if the rendering fails, log and return accordingly
    if not image_data:
        append_to_log(skipped_macro_log, [uml_id, page_id, "Image failed to render"], page_id)
        return None, source_code

    # Return tuple to be used for updating the Confluence page
    return image_data, source_code


def start_plantuml_container():
    """
    Starts a Docker container running the PlantUML server.

    Mounts the `include_files` directory into the container for resolving includes.

    Raises:
        subprocess.CalledProcessError: If the Docker container fails to start.
    """
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


from lxml import etree


def wrap_puml_in_cdata(tree):
    """
    Wraps the content of all <ac:plain-text-body> elements in CDATA.

    Parameters:
        tree (etree._Element): An lxml Element representing the root of the XML tree.

    Returns:
        etree._Element: The modified tree with CDATA wrapped where needed.
    """
    ns = {"ac": "http://atlassian.com/content"}

    for elem in tree.xpath(".//ac:plain-text-body", namespaces=ns):
        # Only wrap if text exists and is not already CDATA
        if elem.text and not isinstance(elem.text, etree.CDATA):
            elem.text = etree.CDATA(elem.text)

    return tree


def add_comment_to_page(page_id, apiAuth, page_log):
    """
    Adds a comment to a Confluence page indicating that it was modified.

    Args:
        page_id (str): The ID of the Confluence page.
        apiAuth (HTTPBasicAuth): The authentication object for API requests.
        page_log (str): The log file for page updates.

    Returns:
        str: A message indicating the result of the operation.
    """
    url = f"https://confluence.service.anz/rest/api/content"

    data = {
        "type": "comment",
        "container": {
            "id": page_id,
            "type": "page"
        },
        "body": {
            "storage": {
                "value": "This page has been updated as part of the automated replacement of the PlantUML macro, in readiness for the upcoming migration to Confluence Cloud. Some or all PlantUML macros on this page have been removed and replaced with screenshots of the most recent diagrams. The corresponding PlantUML source code is included below each image within an Expand macro. For further assistance or inquiries, please contact atlassiancloud@anz.com.",
                "representation": "storage"
            }
        }
    }

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
        return f"Failed to add comment: {response.status_code} - {response.text}"


def runScript(fileName, server_url="http://localhost:8080"):
    """
    Main function to process Confluence pages and replace PlantUML macros.

    Args:
        fileName (str): The name of the file containing the list of page IDs.
        server_url (str): The URL of the PlantUML server (default: "http://localhost:8080").
    """
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
    AC_NS = "http://atlassian.com/content"  # namespace for atlassian content
    RI_NS = "http://atlassian.com/resource/identifier"  # namespace for atlassian resource identifier
    NSMAP = {'ac': AC_NS, 'ri': RI_NS}

    for page_id in page_ids:
        counter = 1

        # print(f"Processing page {page_id}...")

        # no approvals on page so keep going
        # save url for get call
        # Atlassian Confluence REST api endpoints
        getURL = f"https://confluence.service.anz/rest/api/content/{page_id}?expand=body.storage,version"
        attachURL = f"https://confluence.service.anz/rest/api/content/{page_id}/child/attachment"
        updateURL = f"https://confluence.service.anz/rest/api/content/{page_id}"

        # response includes the status code, text etc.
        response = requests.get(getURL, auth=apiAuth, verify=False)

        # check if get request worked correctly
        if response.status_code != 200:
            if response.status_code == 403:
                append_to_log(page_log, [page_id, "No", "403: access not granted"], page_id)
            elif response.status_code == 404:
                append_to_log(page_log, [page_id, "No", "404: page does not exist or access not granted"], page_id)
            elif response.status_code == 502:
                append_to_log(page_log, [page_id, "No", "502: bad gateway, likely proxy error"], page_id)
            else:
                append_to_log(page_log, [page_id, "No", f"{response.status_code}: page not processed"], page_id)
            continue  # do not go through rest of process

        data = response.json()
        current_body = data["body"]["storage"]["value"]
        title = data["title"]
        current_version = data["version"]["number"]

        # print("Current body:\n", current_body) # Just to test

        # Creates an etree parser
        parser = etree.XMLParser(recover=True)

        # Turn our current body into an xml tree so we can process it
        tree = etree.fromstring(f"<root xmlns:ac='http://atlassian.com/content'>{current_body}</root>", parser=parser)

        # print("Current tree:\n", etree.tostring(tree, pretty_print=True).decode()) # Just to test

        # Check for approvals
        if check_approvals(page_id, tree, apiAuth):
            append_to_log(approval_log, [page_id], page_id)
            continue  # do not go through rest of process

        # extracts all plantUML macro nodes
        plantMacros = tree.xpath(
            '//ac:structured-macro[@ac:name="plantuml" or @ac:name="plantumlrender"]',
            namespaces={'ac': 'http://atlassian.com/content'}
        )

        # checks if there are no plantUML macros on the page
        if len(plantMacros) == 0:
            # add to log to indicate no plantUML macros
            append_to_log(page_log, [page_id, "No", "No PlantUML macros found", "N/A"], page_id)
            continue

        total_macros = len(plantMacros)
        failed_macros = 0
        successful_macros = []

        for macro in plantMacros:
            uml_id = f"puml_{page_id}_{str(counter)}"
            counter += 1
            image_data, source_code = process_macro(macro, server_url, uml_id, page_id, skipped_macro_log,
                                                    unresolved_include_log)
        if not image_data:
            failed_macros += 1
            continue
        # Outside the loop, so only the last macro is appended
        successful_macros.append((macro, image_data, source_code, uml_id))

        # If all macros failed, skip update and comment
        if not successful_macros:
            append_to_log(page_log, [page_id, "No", "all plantUML macros were either unresolved or skipped", "N/A"],
                          page_id)
            continue

        for macro, image_data, source_code, uml_id in successful_macros:
            # POST to attach the image to the confluence page
            requests.post(attachURL,
                          auth=apiAuth,
                          headers={"X-Atlassian-Token": "no-check"},
                          files={'file': (f"{uml_id}.png", image_data.getvalue(), 'image/png')},
                          verify=False
                          )

            # Create tree node for uml image
            image_elem = etree.Element("{%s}image" % AC_NS, nsmap=NSMAP)
            attachment_elem = etree.SubElement(image_elem, "{%s}attachment" % RI_NS)
            attachment_elem.set("{%s}filename" % RI_NS, f"{uml_id}.png")

            # Create the hidden macro (expand)
            expand_macro_elem = etree.Element("{%s}structured-macro" % AC_NS, nsmap=NSMAP)
            expand_macro_elem.set("{%s}name" % AC_NS, "expand")

            # Add the title parameter to customize the expand button
            title_elem = etree.SubElement(expand_macro_elem, "{%s}parameter" % AC_NS)
            title_elem.set("{%s}name" % AC_NS, "title")
            title_elem.text = "Show Source Code"

            # Add the rich-text-body to hold the content
            rich_body_elem = etree.SubElement(expand_macro_elem, "{%s}rich-text-body" % AC_NS)

            # Add a pre tag to show the source code as preformatted text
            pre_elem = etree.SubElement(rich_body_elem, "pre")
            pre_elem.text = source_code  # <pre> will preserve formatting

            # get current location of macro for replacement
            parent = macro.getparent()
            macro_index = parent.index(macro)
            parent.remove(macro)

            # Insert image and hidden macro at the same spot
            parent.insert(macro_index, image_elem)
            parent.insert(macro_index + 1, expand_macro_elem)

        # print("modified tree:\n", etree.tostring(tree, pretty_print=True).decode()) # Just to test

        final_tree = wrap_puml_in_cdata(tree)

        # convert etree to string to send to confluence api
        new_body = etree.tostring(final_tree, encoding="unicode")

        # print("modified string:\n", new_body) # Just to test

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

        update_response = requests.put(updateURL, headers=headers, json=payload, auth=apiAuth, verify=False)

        if update_response.status_code == 200:
            comment_message = add_comment_to_page(page_id, apiAuth, page_log)
            append_to_log(page_log, [page_id, "Yes", "Page updated successfully", comment_message], page_id)

        else:
            append_to_log(page_log, [page_id, "No", f"Failed to update page: {update_response.status_code}", "N/A"],
                          page_id)

    # Stop and remove the container
    subprocess.run(["docker", "stop", "plantuml_server"], check=True)
    subprocess.run(["docker", "rm", "plantuml_server"], check=True)

    print("Script finished")


if len(sys.argv) != 2:
    print("Usage: python script.py <filename>")
    sys.exit(1)

filename = sys.argv[1]

runScript(filename)
