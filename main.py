import requests
from requests.auth import HTTPBasicAuth
import os
import rapidjson
from functools import partial, lru_cache
from flask import Flask

os.environ['API_HOST'] = 'https://incident-api.use1stag.elevatesecurity.io'
os.environ['INCIDENTS_ENDPOINT'] = f'{os.environ["API_HOST"]}/incidents'
os.environ['IDENTITIES_ENDPOINT'] = f'{os.environ["API_HOST"]}/identities'
os.environ['API_USER'] = 'elevateinterviews'
os.environ['API_PASS'] = 'ElevateSecurityInterviews2021'


def _resolve_id_from_ip(field: str, src: dict, identities) -> str:
    return identities.lookup_user_by_ip(src[field])


def _extract_id(field: str, src: dict, identities) -> str:
    return str(src[field])


INCIDENT_TYPES = [
    ('denial', partial(_extract_id, 'reported_by')),
    ('intrusion', partial(_resolve_id_from_ip, 'internal_ip')),
    ('executable', partial(_resolve_id_from_ip, 'machine_ip')),
    ('misuse', partial(_extract_id, 'employee_id')),
    ('unauthorized', partial(_extract_id, 'employee_id')),
    ('probing', partial(_resolve_id_from_ip, 'ip')),
    ('other', partial(_extract_id, 'identifier')),
]

PRIORITIES = [
    "low",
    "medium",
    "high",
    "critical",
]


class Identities:
    def __init__(self):
        self.api_endpoint = os.environ['IDENTITIES_ENDPOINT']
        self.api_creds = HTTPBasicAuth(os.environ['API_USER'], os.environ['API_PASS'])
        self.mappings = None

    # TODO validate ip
    def lookup_user_by_ip(self, ip: str) -> str:
        if not self.mappings:
            self.mappings = self._fetch_mapping()
        return str(self.mappings.get(ip, None))

    # TODO error handling
    def _fetch_mapping(self) -> dict:
        resp = requests.get(self.api_endpoint, auth=self.api_creds)
        return resp.json()


class Incidents:

    def __init__(self, identities: Identities):
        self.api_endpoint = os.environ['INCIDENTS_ENDPOINT']
        self.api_creds = HTTPBasicAuth(os.environ['API_USER'], os.environ['API_PASS'])
        self.identities = identities

    def iterate(self):
        for incident_type, id_extractor in INCIDENT_TYPES:
            for incident in self._fetch_incident_type(incident_type).get('results', []):
                yield incident, id_extractor(incident, self.identities)

    # TODO error handling
    @lru_cache(maxsize=len(INCIDENT_TYPES))
    def _fetch_incident_type(self, incident_type: str) -> dict:
        resp = requests.get(f'{self.api_endpoint}/{incident_type}', auth=self.api_creds)
        return resp.json()


class State:

    def __init__(self, incidents: Incidents):
        self.incidents = incidents
        self.state = self._build_state()

    def _build_state(self):

        report = {}
        for incident, user_id in self.incidents.iterate():

            if user_id is None:
                print(f'Unable to detect user for incident: {rapidjson.dumps(incident)}')
                continue

            if incident['priority']:
                priority = incident['priority']
            else:
                print(f'Unable to detect priority for incident: {rapidjson.dumps(incident)}')
                continue
            
            if user_id not in report:
                report[user_id] = {priority: {"count": 0} for priority in PRIORITIES}

            if 'incidents' not in report[user_id][priority]:
                report[user_id][priority]['incidents'] = []

            report[user_id][priority]['incidents'].append(incident)
            report[user_id][priority]['count'] += 1

        return { k: v for (k, v) in sorted(report.items())}

    def get_state(self):
        return self.state


app = Flask(__name__)

__identities = Identities()
__incidents = Incidents(__identities)
__state = State(__incidents)


@app.route("/identities")
def get_identities():
    return rapidjson.dumps(__state.get_state())

