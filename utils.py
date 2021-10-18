import logging
import datetime
import os

ROOT_FOLDER = ""


def get_string_representation(contents):
    border_len = len(max(contents, key=lambda x: len(x)))
    bordered_contents = ["| " + txt.ljust(border_len) + " |" for txt in contents]
    string_rep = "\n" + "="*(border_len+4)+ "\n" + "\n".join(bordered_contents) + "\n"+ "="*(border_len+4) + "\n"
    return string_rep


def log(fname, msg):
    fname = os.path.join(ROOT_FOLDER, f"logs/{fname}.log")
    logging.basicConfig(filename=fname, level=logging.INFO)
    current_ts = datetime.datetime.now().strftime("%m-%d-%Y::%H:%M:%S")
    msg = current_ts+"::"+msg
    logging.info(msg+"\n")
    print("\n",msg,"\n")




