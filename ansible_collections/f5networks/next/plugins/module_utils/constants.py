# -*- coding: utf-8 -*-
#
# Copyright: (c) 2023, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os
import logging

BASE_HEADERS = {'Content-Type': 'application/json'}

LOGIN = '/api/login'
ROOT = '/api'


BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

TEEM_ENDPOINT = 'product.apis.f5.com'
TEEM_KEY = 'mmhJU2sCd63BznXAXDh4kxLIyfIMm3Ar'
TEEM_TIMEOUT = 10
TEEM_VERIFY = False

CICD_ENV = {
    'bamboo.buildKey': 'Bamboo',
    'DRONE': 'Drone CI',
    'BUILDKITE': 'Buildkite',
    'CIRCLECI': 'Circle CI',
    'CIRRUS_CI': 'Cirrus CI',
    'CODEBUILD_BUILD_ID': 'AWS CodeBuild',
    'GITHUB_ACTIONS': 'GitHub Actions',
    'GITLAB_CI': 'GitLab CI',
    'HUDSON_URL': 'Hudson CI',
    'JENKINS_URL': 'Jenkins CI',
    'TF_BUILD': 'Azure Pipelines',
    'HEROKU_TEST_RUN_ID': 'Heroku CI',
    'TEAMCITY_VERSION': 'TeamCity',
    'TRAVIS': 'Travis CI',
    'CI_NAME': 'CodeShip CI'
}

LOG_LEVELS = {
    'debug': logging.DEBUG,
    'info': logging.INFO,
    'warning': logging.WARNING,
    'error': logging.ERROR,
    'critical': logging.CRITICAL,
}
