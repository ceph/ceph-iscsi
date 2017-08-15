#!/usr/bin/python

# prep for python 3
from __future__ import print_function

# requires python2-requests/python3-requests

import logging
import os
import sys
import argparse
import signal

from configshell_fb import ConfigShell, ExecutionError
from gwcli.gateway import ISCSIRoot

import ceph_iscsi_config.settings as settings

__author__ = 'Paul Cuzner'
__version__ = '2.5'


class GatewayCLI(ConfigShell):

    default_prefs = {'color_path': 'magenta',
                     'color_command': 'cyan',
                     'color_parameter': 'magenta',
                     'color_keyword': 'cyan',
                     'completions_in_columns': True,
                     'logfile': None,
                     'loglevel_console': 'info',
                     'loglevel_file': 'debug9',
                     'color_mode': True,
                     'prompt_length': 30,
                     'tree_max_depth': 0,
                     'tree_status_mode': True,
                     'tree_round_nodes': True,
                     'tree_show_root': True,
                     }


def exception_handler(exception_type, exception, traceback,
                      debug_hook=sys.excepthook):

    if options.debug:
        debug_hook(exception_type, exception, traceback)
    else:
        color_red = '\x1b[31;1m'
        color_off = '\x1b[0m'
        print("{}{}: {}{}".format(color_red, exception_type.__name__,
                                  exception, color_off))

def get_options():

    # Set up the runtime overrides, any of these could be provided
    # by the cfg file(s)
    parser = argparse.ArgumentParser(prog='gwcli',
                                     description='Manage iSCSI gateways')
    parser.add_argument('-c', '--config-object', type=str,
                        help='pool and object name holding the iSCSI config'
                             ' object (pool/object_name)')
    parser.add_argument('-d', '--debug', action='store_true',
                        default=False,
                        help='run with additional debug')
    parser.add_argument('-v', '--version', action='version',
                        version='%(prog)s - {}'.format(__version__))
    parser.add_argument('cli_command', type=str, nargs=argparse.REMAINDER)

    # create the opts object
    opts = parser.parse_args()

    # establish defaults, just in case they're missing from the config
    # file(s) AND run time call
    if not opts.config_object:
        opts.config_object = 'rbd/gateway.conf'

    opts.cli_command = ' '.join(opts.cli_command)

    return opts

def kbd_handler(*args):
    pass


def main():
    is_root = True if os.getuid() == 0 else False
    if not is_root:
        print("CLI only supports root level access")
        sys.exit(-1)

    shell = GatewayCLI('~/.gwcli')

    root_node = ISCSIRoot(shell)

    root_node.interactive = False if options.cli_command else True
    settings.config.interactive = False if options.cli_command else True

    # Load the config to populate the object model
    root_node.refresh()
    if root_node.error:
        print("Unable to contact the local API endpoint "
              "({})".format(settings.config.api_endpoint))
        sys.exit(-1)

    # Account for invocation which includes a command to run i.e. batch mode
    if options.cli_command:

        try:
            shell.run_cmdline(options.cli_command)
        except Exception as e:
            print(str(e), file=sys.stderr)
            sys.exit(-1)

        sys.exit(0)

    # Main loop - run the interactive shell, until the user exits
    while not shell._exit:
        try:
            shell.run_interactive()
        except ExecutionError as msg:
            shell.log.error(str(msg))


def log_in_color(fn):

    def new(*args):
        colour_off = '\x1b[0m'
        levelno = args[0].levelno

        if levelno >= logging.CRITICAL:
            color = '\x1b[31;1m'
        elif levelno >= logging.ERROR:
            color = '\x1b[31;1m'
        elif levelno >= logging.WARNING:
            color = '\x1b[33;1m'
        elif levelno >= logging.INFO:
            color = '\x1b[32;1m'
        elif levelno >= logging.DEBUG:
            color = '\x1b[34;1m'
        else:
            color = '\x1b[0m'

        args[0].msg = "{}{}{}".format(color, args[0].msg, colour_off)

        return fn(*args)
    return new

if __name__ == "__main__":
    options = get_options()

    # Setup logging
    log_path = os.path.join(os.path.expanduser("~"), "gwcli.log")

    logger = logging.getLogger('gwcli')
    logger.setLevel(logging.DEBUG)

    file_handler = logging.FileHandler(log_path, mode='a')

    file_format = logging.Formatter('%(asctime)s %(levelname)-8s '
                                    '[%(filename)s:%(lineno)s:%(funcName)s()]'
                                    ' %(message)s')

    file_handler.setFormatter(file_format)
    file_handler.setLevel(logging.DEBUG)
    logger.addHandler(file_handler)

    if not options.cli_command:
        stream_handler = logging.StreamHandler(stream=sys.stdout)
        if options.debug:
            stream_handler.setLevel(logging.DEBUG)
        else:
            stream_handler.setLevel(logging.INFO)

        stream_handler.emit = log_in_color(stream_handler.emit)
        logger.addHandler(stream_handler)

    # Override the default exception handler to only show back traces
    # in debug mode
    sys.excepthook = exception_handler

    # Intercept ctrl-c and ctrl-z events to stop the user exiting
    signal.signal(signal.SIGTSTP, kbd_handler)
    signal.signal(signal.SIGINT, kbd_handler)

    settings.init()

    main()
