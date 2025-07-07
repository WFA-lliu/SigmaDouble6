#! python3

import os
import sys
import argparse
import logging
import re
import socketserver
import threading
import time
import yaml
from datetime import datetime
from datetime import timedelta

DEFAULT_MAPPED_IPV4_ADDRESS: str = "0.0.0.0"
DEFAULT_MAPPED_TCP_PORT_BASE: int = 8051

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass

class EchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.data = None
        self.context = SigmaDouble.get_handle_context()
        self.rsp_latest: str = None
        logging.debug("self.server.args: %s"%(repr(self.server.args)))
        while True:
            try:
                self.data = self.request.recv(2048);
                logging.info("double: %s(:%d); peer: %s:%d"%(self.server.alias, self.server.server_address[1], self.client_address[0], self.client_address[1]))
                if not self.data:
                    # it would be disconnected by client
                    self.context = SigmaDouble.get_handle_context()
                    break
                else:
                    # normal data
                    logging.debug("self.context: %s"%(repr(self.context)))
                    rsp_list = SigmaDouble.handle_req_rsp(self.context, self.server.args, self.data)
                    for rsp in rsp_list:
                        self.rsp_latest = rsp + "\r\n"
                        self.request.sendall(self.rsp_latest.encode("utf-8"))
            except IOError:
                # do nothing
                pass

class EchoServer():
    def __init__(self, host = "localhost", port = 9527, handler = None):
        self.host = host
        self.port = port
        self.handler = handler
        self.server = None

    def run_server(self, args = None, alias = None):
        logging.debug("args: %s" %(repr(args)))
        logging.debug("alias: %s" %(repr(alias)))
        socketserver.TCPServer.allow_reuse_address = True
        self.server = ThreadedTCPServer((self.host, self.port), self.handler)
        self.server.args = args
        self.server.alias = alias
        self.server.serve_forever()

    def shutdown_server(self):
        self.server.shutdown()

class SigmaDouble():
    def __init__(self) -> None:
        pass

    @staticmethod
    def get_dt(ts: str = None) -> datetime:
        fmt: str = "%Y-%m-%d %H:%M:%S.%f"
        dt: datetime = None
        try:
            dt = datetime.strptime(ts, fmt)
        except:
            pass
        return dt

    @staticmethod
    def get_elapsed_time_accumulation_report(fn: str = None, entities: dict = None, rr: dict = None, rpt: str = None) -> bool:
        f = open(rpt, "a")
        for handle in rr:
            alias = entities[handle]["alias"]
            for h in rr[handle]:
                td: datetime = rr[handle][h]["rsp_dt"] - rr[handle][h]["req_dt"]
                capi: str = rr[handle][h]["req"].split(",")[0]
                capi_argv: list = rr[handle][h]["req"].split(",")[1:]
                argv: str = ("\"%s\"" % ("" if len(capi_argv) == 0 else ",".join(capi_argv)))
                print("elapsed: %s; alias: \"%s\"; capi: %s; argv: %s; fn: \"%s\"" % (td.total_seconds(), alias, capi, argv, os.path.basename(fn)), file = f)
        f.flush()
        f.close()
        return True

    @staticmethod
    def get_entity(snippet: str = None, parentheses: bool = True) -> tuple:
        ret_patt_info_search = re.search("INFO - ", snippet)
        ret_patt_parallel_search = re.search("parallelID:\\d+:\\d+:\\s", snippet)
        alias_index_begin: int = ret_patt_info_search.end() if (ret_patt_parallel_search is None) else ret_patt_parallel_search.end()
        alias: str = None
        handle: str = None
        if parentheses == True:
            ret_patt_left_parentheses_search = re.search("\\(", snippet)
            ret_patt_right_parentheses_search = re.search("\\)", snippet)
            alias = snippet[alias_index_begin:ret_patt_left_parentheses_search.start()-1]
            handle = snippet[ret_patt_left_parentheses_search.end():ret_patt_right_parentheses_search.start()]
        else:
            alias = snippet[alias_index_begin:].rstrip()
        return (alias, handle)

    @staticmethod
    def get_entity_list(path: str = None) -> dict:
        entities = dict()
        with open(path) as file:
            for line in file:
                ret_patt_req_search = re.search("INFO - .*\\(.*\\) --->", line)
                if ret_patt_req_search is not None:
                    capi_req_hdl = line[ret_patt_req_search.start():ret_patt_req_search.end()]
                    (alias, handle) = SigmaDouble.get_entity(capi_req_hdl)
                    if len(alias) == 0:
                        if handle in entities:
                            logging.debug("empty; handle: %s; alias: %s" %(handle, entities[handle]["alias"]))
                        else:
                            entities[handle] = dict()
                            entities[handle]["alias"] = "Unknown"
                            entities[handle]["mapped_ipv4"] = None
                            entities[handle]["mapped_port"] = None
                    else:
                        entities[handle] = dict()
                        entities[handle]["alias"] = alias
                        entities[handle]["mapped_ipv4"] = None
                        entities[handle]["mapped_port"] = None
                else:
                    pass
        return entities

    @staticmethod
    def is_rsp_valid(rsp: str = None) -> bool:
        ret_patt_rsp_search0 = re.search("^status", rsp)
        return False if ret_patt_rsp_search0 is None else True

    @staticmethod
    def get_req_rsp(path: str = None, hdl: str = None, al: str = None) -> dict:
        logging.debug("hdl: %s"%(hdl))
        logging.debug("al: %s"%(al))
        rst = dict()
        STATE_REQ: int = 0
        STATE_RSP: int = 1
        cnt: int = 0
        tmp_req: str = None
        tmp_rsp: list = list()
        tmp_req_dt: datetime = None
        tmp_rsp_dt: datetime = None
        # one req might have multiple rsp
        with open(path) as file:
            for line in file:
                ret_patt_req_search = re.search("INFO - .*\\(.*\\) --->\\s", line)
                patt_rsp = "<--"
                ret_patt_rsp_search1 = re.search("INFO - .*\\(.*\\) <----\\s+", line)
                ret_patt_rsp_search4 = re.search("INFO - .*\\(.*\\) <---\\s+", line)
                ret_patt_rsp_search2 = re.search("INFO - .*<--\\d+\\s", line)
                ret_patt_rsp_search3 = re.search("INFO - .*\\(.*\\) <--\\s+", line)
                if ret_patt_req_search is not None:
                    capi_req_hdl = line[ret_patt_req_search.start():ret_patt_req_search.end()]
                    dt = SigmaDouble.get_dt(line[:ret_patt_req_search.start()-3])
                    #logging.debug("capi_req_hdl: %s" %(capi_req_hdl))
                    (alias, handle) = SigmaDouble.get_entity(capi_req_hdl)
                    if handle == hdl:
                        capi_req: str = line[ret_patt_req_search.end():].rstrip()
                        logging.debug("capi_req: %s" % (repr(capi_req)))
                        if len(tmp_rsp) > 0:
                            rst[cnt] = dict()
                            rst[cnt]["req"] = tmp_req
                            rst[cnt]["req_dt"] = tmp_req_dt
                            rst[cnt]["rsp"] = tmp_rsp.copy()
                            rst[cnt]["rsp_dt"] = tmp_rsp_dt
                            logging.debug("rst[%d]: %s"%(cnt, repr(rst[cnt])))
                            cnt += 1
                            tmp_req = None
                            tmp_rsp.clear()
                        else:
                            pass
                        tmp_req_dt = dt
                        tmp_req = capi_req
                        state = STATE_RSP
                elif ret_patt_rsp_search1 is not None:
                    ret_patt_rsp_search0 = re.search(patt_rsp, line)
                    capi_rsp_hdl = line[ret_patt_rsp_search1.start():ret_patt_rsp_search0.start()]
                    dt = SigmaDouble.get_dt(line[:ret_patt_rsp_search1.start()-3])
                    #logging.debug("capi_rsp_hdl: %s" %(capi_rsp_hdl))
                    (alias, handle) = SigmaDouble.get_entity(capi_rsp_hdl, True)
                    if handle == hdl:
                        capi_rsp: str = line[ret_patt_rsp_search1.end():].rstrip()
                        logging.debug("capi_rsp: %s" % (repr(capi_rsp)))
                        if SigmaDouble.is_rsp_valid(capi_rsp):
                            tmp_rsp_dt = dt
                            tmp_rsp.append(capi_rsp)
                elif ret_patt_rsp_search4 is not None:
                    ret_patt_rsp_search0 = re.search(patt_rsp, line)
                    capi_rsp_hdl = line[ret_patt_rsp_search4.start():ret_patt_rsp_search0.start()]
                    dt = SigmaDouble.get_dt(line[:ret_patt_rsp_search4.start()-3])
                    #logging.debug("capi_rsp_hdl: %s" %(capi_rsp_hdl))
                    (alias, handle) = SigmaDouble.get_entity(capi_rsp_hdl, True)
                    if handle == hdl:
                        capi_rsp: str = line[ret_patt_rsp_search4.end():].rstrip()
                        logging.debug("capi_rsp: %s" % (repr(capi_rsp)))
                        if SigmaDouble.is_rsp_valid(capi_rsp):
                            tmp_rsp_dt = dt
                            tmp_rsp.append(capi_rsp)
                elif ret_patt_rsp_search2 is not None:
                    ret_patt_rsp_search0 = re.search(patt_rsp, line)
                    capi_rsp_hdl = line[ret_patt_rsp_search2.start():ret_patt_rsp_search0.start()]
                    dt = SigmaDouble.get_dt(line[:ret_patt_rsp_search2.start()-3])
                    #logging.debug("capi_rsp_hdl: %s" %(capi_rsp_hdl))
                    (alias, handle) = SigmaDouble.get_entity(capi_rsp_hdl, False)
                    if alias == al:
                        capi_rsp: str = line[ret_patt_rsp_search2.end():].rstrip()
                        logging.debug("capi_rsp: %s" % (repr(capi_rsp)))
                        if SigmaDouble.is_rsp_valid(capi_rsp):
                            tmp_rsp_dt = dt
                            tmp_rsp.append(capi_rsp)
                elif ret_patt_rsp_search3 is not None:
                    ret_patt_rsp_search0 = re.search(patt_rsp, line)
                    capi_rsp_hdl = line[ret_patt_rsp_search3.start():ret_patt_rsp_search0.start()]
                    dt = SigmaDouble.get_dt(line[:ret_patt_rsp_search3.start()-3])
                    #logging.debug("capi_rsp_hdl: %s" %(capi_rsp_hdl))
                    (alias, handle) = SigmaDouble.get_entity(capi_rsp_hdl, True)
                    if handle == hdl:
                        capi_rsp: str = line[ret_patt_rsp_search3.end():].rstrip()
                        logging.debug("capi_rsp: %s" % (repr(capi_rsp)))
                        if SigmaDouble.is_rsp_valid(capi_rsp):
                            tmp_rsp_dt = dt
                            tmp_rsp.append(capi_rsp)
                else:
                    pass
            if tmp_req is not None:
                rst[cnt] = dict()
                rst[cnt]["req"] = tmp_req
                rst[cnt]["req_dt"] = tmp_req_dt
                rst[cnt]["rsp"] = tmp_rsp.copy()
                rst[cnt]["rsp_dt"] = tmp_rsp_dt
                logging.debug("rst[%d]: %s"%(cnt, repr(rst[cnt])))
                cnt += 1
                tmp_req = None
                tmp_rsp.clear()
        return rst

    @staticmethod
    def get_req_rsp_list(path: str = None, entities: dict = None) -> dict:
        rst = dict()
        for handle in entities:
            logging.debug("handle: %s; data: %s"%(handle, entities[handle]))
            rst[handle] = SigmaDouble.get_req_rsp(args.filename, handle, entities[handle]["alias"])
        return rst

    @staticmethod
    def get_handle_context() -> dict:
        ctx = dict()
        ctx["stateful"] = True
        ctx["cnt"] = 0
        return ctx

    @staticmethod
    def handle_req_rsp(ctx: dict = None, rr: dict = None, req: str = None) -> list:
        rsp = None
        if ctx["stateful"] == True:
            if ctx["cnt"] < len(rr):
                # replay existing response
                rsp = rr[(ctx["cnt"])]["rsp"]
                patt_rsp = "status,RUNNING"
                ret_patt_rsp_search0 = re.search(patt_rsp, rsp[0])
                if ret_patt_rsp_search0 is None:
                    rsp.insert(0, patt_rsp)
            else:
                # default response, extra argument is added for debugging usage
                rsp = list()
                rsp.append(str("status,COMPLETE,extra,AUXILIARY"))
            ctx["cnt"] += 1
        logging.debug("rsp: %s"%(repr(rsp)))
        return rsp

    @staticmethod
    def start_double(entities: dict = None, rr: dict = None):
        cnt: int = 0
        es_list = dict()
        est_list = dict()
        for handle in rr:
            host = entities[handle]["mapped_ipv4"]
            port = entities[handle]["mapped_port"]
            es = EchoServer(host, port, EchoHandler)
            est = threading.Thread(target=es.run_server, args=(rr[handle], entities[handle]["alias"], ))
            est.deamon = False
            est.start()
            es_list[cnt] = es
            est_list[cnt] = est
            logging.debug("cnt: %s"%(cnt))
            cnt += 1
        return (es_list, est_list)

    @staticmethod
    def stop_double(es: dict = None, est: dict = None) -> None:
        for cnt in es:
            es[cnt].shutdown_server()

if __name__ == "__main__":
    my_parser = argparse.ArgumentParser(description="CLI argument parsing")
    my_parser.add_argument("-v",
        "--verbose",
        action="store_true",
        help="verbosity")
    my_parser.add_argument("-a",
        "--accumulated",
        action="store_true",
        help="elapsed time accumulated mode of each CAPI")
    my_parser.add_argument("-r",
        "--report",
        metavar="report",
        default="sigmadouble6-report.txt",
        type=str,
        help="filename of report for elapsed time accumulated mode")
    my_parser.add_argument("-f",
        "--filename",
        metavar="filename",
        default="",
        type=str,
        help="filename of UCC log")
    my_parser.add_argument("-i",
        "--ip",
        metavar="mapped_ipv4",
        default=DEFAULT_MAPPED_IPV4_ADDRESS,
        type=str,
        help="mapped IPv4 address; only for mapping stored filename")
    my_parser.add_argument("-p",
        "--port",
        metavar="mapped_port_base",
        default=DEFAULT_MAPPED_TCP_PORT_BASE,
        type=int,
        help="mapped TCP listening port base; only for mapping stored filename")
    my_parser.add_argument("-e",
        "--exclude",
        metavar="exclude",
        default=None,
        type=str,
        help="excluding handle (ipv4:port formatted)")
    my_parser_group = my_parser.add_mutually_exclusive_group()
    my_parser_group.add_argument("-s",
        "--store",
        metavar="mapping_stored_filename",
        default=None,
        type=str,
        help="mapping stored filename, from UCC log; YAML formatted")
    my_parser_group.add_argument("-l",
        "--load",
        metavar="mapping_loaded_filename",
        default=None,
        type=str,
        help="mapping loaded filename, to UCC log; YAML formatted")
    args = my_parser.parse_args()

    if args.verbose == True :
        logging.basicConfig(level=logging.INFO)
    else:
        logging.basicConfig(level=logging.ERROR)
    logging.debug("args: " + repr(args))

    entity_list = SigmaDouble.get_entity_list(args.filename)
    #logging.info("entity_list: %s"%(repr(entity_list)))

    if args.store is not None:
        if len(entity_list) <= 1:
            logging.warning("invalid: %s"%(args.filename))
            sys.exit(1)
        else:
            port: int = args.port
            ip: str = args.ip
            for handle in entity_list:
                entity_list[handle]["mapped_ipv4"] = ip
                entity_list[handle]["mapped_port"] = port
                port += 1
            try:
                with open(args.store, "w",) as f :
                    yaml.dump(entity_list, f, sort_keys=True)
            except:
                logging.warning("invalid: %s"%(args.store))
                sys.exit(1)
        sys.exit(0)

    if args.load is not None:
        loaded: dict = None
        try:
            with open(args.load, "r") as f:
                loaded = yaml.safe_load(f)
            #logging.info("loaded: %s"%(repr(loaded)))
        except:
            logging.warning("invalid: %s"%(args.load))
        if loaded is not None:
            entity_list.clear()
            entity_list = loaded
        #logging.info("entity_list: %s"%(repr(entity_list)))

    cnt: int = 0
    for handle in entity_list:
        host: str = DEFAULT_MAPPED_IPV4_ADDRESS
        port: int = DEFAULT_MAPPED_TCP_PORT_BASE + cnt
        if entity_list[handle]["mapped_ipv4"] is None or entity_list[handle]["mapped_port"] is None:
            entity_list[handle]["mapped_ipv4"] = host
            entity_list[handle]["mapped_port"] = port
            logging.info("alias: %s, ipv4: %s, port: %d; default"%(entity_list[handle]["alias"], entity_list[handle]["mapped_ipv4"], entity_list[handle]["mapped_port"]))
        cnt += 1
    logging.info("%s QTY: %d" % ("original", cnt))

    req_rsp_list = SigmaDouble.get_req_rsp_list(args.filename, entity_list)
    #logging.info("req_rsp_list: %s"%(repr(req_rsp_list)))

    if args.accumulated == True:
        #create an empty file
        with open(args.report, 'w') as f:
            pass
        SigmaDouble.get_elapsed_time_accumulation_report(args.filename, entity_list, req_rsp_list, args.report)
        sys.exit(0)

    if args.exclude is not None:
        removed_entry: dict = entity_list.pop(args.exclude, None)
        removed_req_rsp: dict = req_rsp_list.pop(args.exclude, None)
        logging.debug("removed_entry: %s"%(repr(removed_entry)))
        logging.debug("removed_req_rsp: %s"%(repr(removed_req_rsp)))
        excluded_cnt: int = 0
        for handle in entity_list:
            logging.info("alias: %s, ipv4: %s, port: %d; default"%(entity_list[handle]["alias"], entity_list[handle]["mapped_ipv4"], entity_list[handle]["mapped_port"]))
            excluded_cnt += 1
        logging.info("%s QTY: %d" % ("excluded", excluded_cnt))

    try:
        es, est = SigmaDouble.start_double(entity_list, req_rsp_list)
        # wait forever
        for cnt in est:
            est[cnt].join()
    except KeyboardInterrupt:
        logging.debug("Ctrl-C or alike is pressed...")
    finally:
        SigmaDouble.stop_double(es, est)
    sys.exit(0)

#SigmaDouble6 - by Leo Liu
