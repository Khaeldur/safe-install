"""Gap 8: CI/CD integration - detect CI, generate JSON/SARIF/SBOM reports."""

import datetime
import json
import os
from .core import c


class CIDetector:
    CI_VARS = {
        'GITHUB_ACTIONS': 'github', 'GITLAB_CI': 'gitlab',
        'CIRCLECI': 'circleci', 'TRAVIS': 'travis',
        'JENKINS_URL': 'jenkins', 'BUILDKITE': 'buildkite',
        'CODEBUILD_BUILD_ID': 'aws-codebuild', 'TF_BUILD': 'azure-devops',
        'BITBUCKET_PIPELINE_UUID': 'bitbucket', 'DRONE': 'drone',
    }

    def __init__(self):
        self.ci_name = self.detect()

    def detect(self):
        for var, name in self.CI_VARS.items():
            if os.environ.get(var):
                return name
        return None

    def is_ci(self):
        return self.ci_name is not None


class CIReporter:
    def __init__(self):
        self.findings = {}
        self.metadata = {}

    def set_metadata(self, package, ecosystem, deps=None):
        self.metadata = {
            'package': package, 'ecosystem': ecosystem,
            'deps': deps or [],
            'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }

    def add_findings(self, source, findings):
        if findings:
            self.findings[source] = findings

    def generate_json(self):
        return json.dumps({
            'version': '1.0', 'tool': 'safe-install',
            'metadata': self.metadata,
            'summary': {
                'total': sum(len(f) for f in self.findings.values()),
                'by_severity': self._count_severity(),
            },
            'findings': self.findings,
        }, indent=2, default=str)

    def generate_sarif(self):
        results = []
        for source, findings in self.findings.items():
            for f in findings:
                r = {
                    'ruleId': f.get('pattern', source),
                    'level': {'CRITICAL': 'error', 'HIGH': 'error',
                              'MEDIUM': 'warning'}.get(f.get('severity', 'MEDIUM'), 'note'),
                    'message': {'text': f.get('pattern', f.get('message', str(f)))},
                }
                if 'file' in f and 'line' in f:
                    r['locations'] = [{'physicalLocation': {
                        'artifactLocation': {'uri': f['file']},
                        'region': {'startLine': f['line']},
                    }}]
                results.append(r)
        return json.dumps({
            '$schema': 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
            'version': '2.1.0',
            'runs': [{'tool': {'driver': {'name': 'safe-install', 'version': '0.1.0'}},
                       'results': results}],
        }, indent=2)

    def generate_sbom(self):
        components = []
        if self.metadata.get('package'):
            components.append({'type': 'library', 'name': self.metadata['package'],
                               'purl': f"pkg:{self.metadata.get('ecosystem', 'pypi')}/{self.metadata['package']}"})
        for dep in self.metadata.get('deps', []):
            components.append({'type': 'library', 'name': dep.get('name', ''),
                               'version': dep.get('version', ''),
                               'purl': f"pkg:{self.metadata.get('ecosystem', 'pypi')}/{dep.get('name', '')}@{dep.get('version', '')}"})
        return json.dumps({
            'bomFormat': 'CycloneDX', 'specVersion': '1.5', 'version': 1,
            'metadata': {'timestamp': self.metadata.get('timestamp', ''),
                         'tools': [{'name': 'safe-install', 'version': '0.1.0'}]},
            'components': components,
        }, indent=2)

    def write_reports(self, output_dir, formats=None):
        formats = formats or ['json']
        os.makedirs(output_dir, exist_ok=True)
        written = []
        gens = {'json': ('report.json', self.generate_json),
                'sarif': ('report.sarif', self.generate_sarif),
                'sbom': ('sbom.json', self.generate_sbom)}
        for fmt in formats:
            if fmt in gens:
                fname, gen = gens[fmt]
                path = os.path.join(output_dir, f'safe-install-{fname}')
                with open(path, 'w') as f:
                    f.write(gen())
                written.append(path)
                print(f"  {c('Report:', 'green')} {path}")
        return written

    def _count_severity(self):
        counts = {}
        for findings in self.findings.values():
            for f in findings:
                s = f.get('severity', 'MEDIUM')
                counts[s] = counts.get(s, 0) + 1
        return counts


class CIMode:
    def __init__(self, config=None):
        self.config = config or {}
        ci_cfg = self.config.get("ci", {})
        self.auto_detect = ci_cfg.get("auto_detect", True)
        self.fail_critical = ci_cfg.get("fail_on_critical", True)
        self.report_formats = ci_cfg.get("report_formats", ["json"])
        self.detector = CIDetector()
        self.reporter = CIReporter()

    def should_activate(self):
        return self.auto_detect and self.detector.is_ci()

    def get_exit_code(self, all_findings):
        if not self.fail_critical:
            return 0
        for findings in (all_findings if isinstance(all_findings, list) else [all_findings]):
            if isinstance(findings, list):
                if any(f.get('severity') == 'CRITICAL' for f in findings):
                    return 1
        return 0
