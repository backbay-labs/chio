"""Intentionally unsafe source for the review application; never executed."""

import hashlib
import subprocess


def evaluate_expression(expression):
    return eval(expression)


def run_export(command):
    return subprocess.run(command, shell=True)


def digest_record(record):
    return hashlib.md5(record).hexdigest()
