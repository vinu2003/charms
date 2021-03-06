# Copyright 2016 Canonical Limited.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from charmhelpers.core.hookenv import (
    log,
    DEBUG,
)
from charmhelpers.contrib.hardening.ssh.checks import config


def run_ssh_checks():
    log("Starting SSH hardening checks.", level=DEBUG)
    checks = config.get_audits()
    for check in checks:
        log("Running '%s' check" % (check.__class__.__name__), level=DEBUG)
        check.ensure_compliance()

    log("SSH hardening checks complete.", level=DEBUG)
