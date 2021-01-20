import argparse
import logging
from synology import Synology
import sys

# Log Levels
logging.getLogger().addHandler(logging.StreamHandler())
root = logging.getLogger()
root.setLevel(logging.INFO)


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
