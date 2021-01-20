import argparse
import json
import logging
import os
import requests
import socket
import sys
from urllib.parse import urlencode, quote_plus

# Log Levels
logging.getLogger().addHandler(logging.StreamHandler())
root = logging.getLogger()
root.setLevel(logging.INFO)


class Synology(object):
    def __init__(self, host, port, username, password, output_path):
        self.dsm_host = host
        self.dsm_port = port
        self.user_name = username
        self.password = password
        self.output_path = output_path
        self.syno_server_url = "https://{}:{}".format(self.dsm_host, self.dsm_port)
        self.sid = None
        self.SynoToken = None

    def connect(self):
        params = {
            "account": self.user_name,
            "passwd": self.password,
            "enable_syno_token": "yes",
            "enable_device_token": "no",
            "device_name": socket.gethostname(),
            "format": "sid",
            "api": "SYNO.API.Auth",
            "version": "6",
            "method": "login",
        }
        with requests.Session() as s:
            requests.packages.urllib3.disable_warnings()  # Disable SSL Warnings
            encoded_uri = urlencode(params, quote_via=quote_plus)  # Python3
            auth_url = "{}/webapi/auth.cgi?{}".format(self.syno_server_url, encoded_uri)
            response = s.get(auth_url, verify=False)
            if response.json().get("success", False):
                logging.info("Logged into DSM Successfully")
                self.sid = response.json()["data"]["sid"]
                self.SynoToken = response.json()["data"]["synotoken"]
            else:
                logging.error("Failed to log into DSM: %s", response.content)
                exit(1)  # Exit with Error

    def get_docker_images(self):
        """Pull Docker Image Names"""
        headers = {
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "X-SYNO-TOKEN": self.SynoToken,
        }

        cookies = {
            "id": self.sid,
        }

        payload = {
            "api": "SYNO.Docker.Container",
            "method": "list",
            "version": "1",
            "limit": "-1",
            "offset": "0",
            "type": "all",
        }
        result = requests.Session().post(
            "{}/webapi/entry.cgi".format(self.syno_server_url),
            cookies=cookies,
            data=payload,
            headers=headers,
            verify=False,
        )
        containers = []
        for container in result.json()["data"].get("containers", []):
            containers.append(container.get("name"))
        return containers

    def get_docker_backup(self, image):
        """Pull Docker Config and Write to file"""
        cookies = {
            "id": self.sid,
        }

        docker_url = "{}/webapi/entry.cgi?api=SYNO.Docker.Container.Profile&method=export&version=1&name=%22{}%22&SynoToken={}".format(
            self.syno_server_url, image, self.SynoToken
        )
        response = requests.Session().get(docker_url, cookies=cookies, verify=False)

        if 200 <= response.status_code < 203:
            logging.info("Successfully pulled {} config.".format(image))
            file_path = os.path.join(self.output_path, "{}.json".format(image))

            # Write Config File
            syno_docker_config_file = open(file_path, "w")
            syno_docker_config_file.write(json.dumps(response.json(), indent=4))
            syno_docker_config_file.close()
            logging.info(
                "Successfully Backed up container config to: %s%s.json",
                self.output_path,
                image,
            )
        else:
            logging.error(
                "Unable to pull image {}: %s".format(image),
                response.content,
            )

    def start_docker_container(self, image):
        """Start Docker Container"""
        cookies = {
            "id": self.sid,
        }

        docker_url = "{}/webapi/entry.cgi?api=SYNO.Docker.Container&method=start&version=1&name=%22{}%22&SynoToken={}".format(
            self.syno_server_url, image, self.SynoToken
        )
        response = requests.Session().get(docker_url, cookies=cookies, verify=False)

        if 200 <= response.status_code < 203:
            logging.info("Successfully started {}.".format(image))
        else:
            logging.error(
                "Unable to start image {}: %s".format(image),
                response.content,
            )

    def stop_docker_container(self, image):
        """Stop Docker Container"""
        cookies = {
            "id": self.sid,
        }

        docker_url = "{}/webapi/entry.cgi?api=SYNO.Docker.Container&method=stop&version=1&name=%22{}%22&SynoToken={}".format(
            self.syno_server_url, image, self.SynoToken
        )
        response = requests.Session().get(docker_url, cookies=cookies, verify=False)

        if 200 <= response.status_code < 203:
            logging.info("Successfully stopped {}.".format(image))
        else:
            logging.error(
                "Unable to stop image {}: %s".format(image),
                response.content,
            )

    def restart_docker_container(self, image):
        """Stop Docker Container"""
        cookies = {
            "id": self.sid,
        }

        docker_url = "{}/webapi/entry.cgi?api=SYNO.Docker.Container&method=restart&version=1&name=%22{}%22&SynoToken={}".format(
            self.syno_server_url, image, self.SynoToken
        )
        response = requests.Session().get(docker_url, cookies=cookies, verify=False)

        if 200 <= response.status_code < 203:
            logging.info("Successfully restarted {}.".format(image))
        else:
            logging.error(
                "Unable to restart image {}: %s".format(image),
                response.content,
            )


def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--task", help="Start/Stop/Restart/Backup", required=True)
    parser.add_argument(
        "-n",
        "--name",
        help="Case sensitive name of container for task. Leave blank for all",
        required=False,
    )
    parser.add_argument("-i", "--ip", help="NAS host address", required=True)
    parser.add_argument("-p", "--port", required=True, default=443)
    parser.add_argument("-u", "--user_name", required=True, default="")
    parser.add_argument("-pass", "--password", required=True, default="")
    parser.add_argument("-o", "--output_path", required=False, default="")
    args = parser.parse_args()
    dsm = Synology(args.ip, args.port, args.user_name, args.password, args.output_path)
    dsm.connect()
    if args.task and args.name:
        task = args.task.lower()
        name = args.name
        if task == "start":
            dsm.start_docker_container(name)
        elif task == "stop":
            dsm.stop_docker_container(name)
        elif task == "restart":
            dsm.restart_docker_container(name)
        elif task == "backup":
            if args.output_path:
                dsm.get_docker_backup(name)
            else:
                logging.error("If taking a backup, you must provide an output_path.")
                exit(1)
    elif args.task and not args.name:
        task = args.task.lower()
        for name in dsm.get_docker_images():
            logging.debug("Found Container: %s", name)
            if task == "start":
                dsm.start_docker_container(name)
            elif task == "stop":
                dsm.stop_docker_container(name)
            elif task == "restart":
                dsm.restart_docker_container(name)
            elif task == "backup":
                if args.output_path:
                    dsm.get_docker_backup(name)
                else:
                    logging.error(
                        "If taking a backup, you must provide an output_path."
                    )
                    exit(1)


if __name__ == "__main__":
    main(sys.argv[1:])
