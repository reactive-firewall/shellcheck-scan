#! /usr/bin/env python
# -*- coding: utf-8 -*-


################################################################################
# DO NOT REMOVE THIS COMMENT WHILE BUNDLED
# This python code is released under MIT when considered as its own and (c) 2024 Mr. Walls.
#
# Regarding this copy:
# This code is re-released under GPLv3 when part of reactive-firewall/shellcheck-scan GHA as a
# whole and is expressly noted here as being derived from the MIT version prior to inclusion
# in the GHA project, where it is both
# released under MIT License,
# and concurently,
# included under the GPLv3 (see GPLv3 for details) when bundled as a full GHA.
################################################################################


# Formally:


# ShellcheckCLI.py (Python Tool Wrapper)
# ..................................
# Copyright (c) 2024-2025, Mr. Walls
# ..................................
# Licensed under MIT (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# ..........................................
# https://www.github.com/reactive-firewall/multicast/LICENSE.md
# ..........................................
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Disclaimer of Warranties.
# A. YOU EXPRESSLY ACKNOWLEDGE AND AGREE THAT, TO THE EXTENT PERMITTED BY
#    APPLICABLE LAW, USE OF THIS SHELL SCRIPT AND ANY SERVICES PERFORMED
#    BY OR ACCESSED THROUGH THIS SHELL SCRIPT IS AT YOUR SOLE RISK AND
#    THAT THE ENTIRE RISK AS TO SATISFACTORY QUALITY, PERFORMANCE, ACCURACY AND
#    EFFORT IS WITH YOU.
#
# B. TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW, THIS SHELL SCRIPT
#    AND SERVICES ARE PROVIDED "AS IS" AND "AS AVAILABLE", WITH ALL FAULTS AND
#    WITHOUT WARRANTY OF ANY KIND, AND THE AUTHOR OF THIS SHELL SCRIPT'S LICENSORS
#    (COLLECTIVELY REFERRED TO AS "THE AUTHOR" FOR THE PURPOSES OF THIS DISCLAIMER)
#    HEREBY DISCLAIM ALL WARRANTIES AND CONDITIONS WITH RESPECT TO THIS SHELL SCRIPT
#    SOFTWARE AND SERVICES, EITHER EXPRESS, IMPLIED OR STATUTORY, INCLUDING, BUT
#    NOT LIMITED TO, THE IMPLIED WARRANTIES AND/OR CONDITIONS OF
#    MERCHANTABILITY, SATISFACTORY QUALITY, FITNESS FOR A PARTICULAR PURPOSE,
#    ACCURACY, QUIET ENJOYMENT, AND NON-INFRINGEMENT OF THIRD PARTY RIGHTS.
#
# C. THE AUTHOR DOES NOT WARRANT AGAINST INTERFERENCE WITH YOUR ENJOYMENT OF THE
#    THE AUTHOR's SOFTWARE AND SERVICES, THAT THE FUNCTIONS CONTAINED IN, OR
#    SERVICES PERFORMED OR PROVIDED BY, THIS SHELL SCRIPT WILL MEET YOUR
#    REQUIREMENTS, THAT THE OPERATION OF THIS SHELL SCRIPT OR SERVICES WILL
#    BE UNINTERRUPTED OR ERROR-FREE, THAT ANY SERVICES WILL CONTINUE TO BE MADE
#    AVAILABLE, THAT THIS SHELL SCRIPT OR SERVICES WILL BE COMPATIBLE OR
#    WORK WITH ANY THIRD PARTY SOFTWARE, APPLICATIONS OR THIRD PARTY SERVICES,
#    OR THAT DEFECTS IN THIS SHELL SCRIPT OR SERVICES WILL BE CORRECTED.
#    INSTALLATION OF THIS THE AUTHOR SOFTWARE MAY AFFECT THE USABILITY OF THIRD
#    PARTY SOFTWARE, APPLICATIONS OR THIRD PARTY SERVICES.
#
# D. YOU FURTHER ACKNOWLEDGE THAT THIS SHELL SCRIPT AND SERVICES ARE NOT
#    INTENDED OR SUITABLE FOR USE IN SITUATIONS OR ENVIRONMENTS WHERE THE FAILURE
#    OR TIME DELAYS OF, OR ERRORS OR INACCURACIES IN, THE CONTENT, DATA OR
#    INFORMATION PROVIDED BY THIS SHELL SCRIPT OR SERVICES COULD LEAD TO
#    DEATH, PERSONAL INJURY, OR SEVERE PHYSICAL OR ENVIRONMENTAL DAMAGE,
#    INCLUDING WITHOUT LIMITATION THE OPERATION OF NUCLEAR FACILITIES, AIRCRAFT
#    NAVIGATION OR COMMUNICATION SYSTEMS, AIR TRAFFIC CONTROL, LIFE SUPPORT OR
#    WEAPONS SYSTEMS.
#
# E. NO ORAL OR WRITTEN INFORMATION OR ADVICE GIVEN BY THE AUTHOR
#    SHALL CREATE A WARRANTY. SHOULD THIS SHELL SCRIPT OR SERVICES PROVE DEFECTIVE,
#    YOU ASSUME THE ENTIRE COST OF ALL NECESSARY SERVICING, REPAIR OR CORRECTION.
#
#    Limitation of Liability.
# F. TO THE EXTENT NOT PROHIBITED BY APPLICABLE LAW, IN NO EVENT SHALL THE AUTHOR
#    BE LIABLE FOR PERSONAL INJURY, OR ANY INCIDENTAL, SPECIAL, INDIRECT OR
#    CONSEQUENTIAL DAMAGES WHATSOEVER, INCLUDING, WITHOUT LIMITATION, DAMAGES
#    FOR LOSS OF PROFITS, CORRUPTION OR LOSS OF DATA, FAILURE TO TRANSMIT OR
#    RECEIVE ANY DATA OR INFORMATION, BUSINESS INTERRUPTION OR ANY OTHER
#    COMMERCIAL DAMAGES OR LOSSES, ARISING OUT OF OR RELATED TO YOUR USE OR
#    INABILITY TO USE THIS SHELL SCRIPT OR SERVICES OR ANY THIRD PARTY
#    SOFTWARE OR APPLICATIONS IN CONJUNCTION WITH THIS SHELL SCRIPT OR
#    SERVICES, HOWEVER CAUSED, REGARDLESS OF THE THEORY OF LIABILITY (CONTRACT,
#    TORT OR OTHERWISE) AND EVEN IF THE AUTHOR HAS BEEN ADVISED OF THE
#    POSSIBILITY OF SUCH DAMAGES. SOME JURISDICTIONS DO NOT ALLOW THE EXCLUSION
#    OR LIMITATION OF LIABILITY FOR PERSONAL INJURY, OR OF INCIDENTAL OR
#    CONSEQUENTIAL DAMAGES, SO THIS LIMITATION MAY NOT APPLY TO YOU. In no event
#    shall THE AUTHOR's total liability to you for all damages (other than as may
#    be required by applicable law in cases involving personal injury) exceed
#    the amount of five dollars ($5.00). The foregoing limitations will apply
#    even if the above stated remedy fails of its essential purpose.
################################################################################

import argparse
import subprocess
import json
import requests
import sarif_om as sarif
from typing import Dict, List, Optional
from urllib.parse import quote

class ShellCheckCLI:
	SARIF_SCHEMA_URL = str(
		"https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/schemas/sarif-schema-2.1.0.json"
	)

	SHELL_LANGUAGE_MAP = {
		"bash": "bash",
		"sh": "shell",
		"dash": "shell",
		"ksh": "ksh",
		"busybox": "shell"
	}

	def __init__(self, shell: str, severity: str, files: List[str]):
		self.shell = shell
		self.severity = severity
		self.files = files
		self.rule_docs_cache: Dict[str, str] = {}

	def fetch_rule_doc(self, code: str) -> Optional[str]:
		"""Fetch the rule documentation from ShellCheck wiki."""
		if code in self.rule_docs_cache:
			print(f"::debug::HIT! Fetching rule details from cache.")
			return self.rule_docs_cache[code]

		url = f"https://raw.githubusercontent.com/wiki/koalaman/shellcheck/{code}.md"
		try:
			print(f"::debug::Fetching rule details from '{url}'")
			response = requests.get(url, timeout=5)
			if response.status_code == 200:
				content = response.text
				print(f"::debug::Fetched rule details successfully. Caching.")
				# Cache the content for future use
				self.rule_docs_cache[code] = content
				print(f"::debug::Fetched rule details and chached successfully.")
				return content
		except requests.RequestException as e:
			print(f"::warning file={__file__},title='Error fetching rule doc':: {e}")
		return None

	def run_shellcheck(self):
		"""Run shellcheck with the specified arguments and return the JSON output."""
		command = [
			"shellcheck",
			f"--shell={self.shell}",
			f"--severity={self.severity}",
			"--format=json1",
			"--check-sourced"  # Include sourced files
		] + self.files
		try:
			result = subprocess.run(command, capture_output=True, text=True, check=True)
			return json.loads(result.stdout)
		except subprocess.CalledProcessError as e:
			print(f"::warning file={__file__},title='Error running shellcheck':: {e}")
			if e.stderr:
				print(f"::warning file=shellcheck,title='Error from shellcheck':: {e.stderr}")
				print("")
			return json.loads(e.stdout)

	def create_fix(self, file: str, fix_data: dict) -> sarif.Fix:
		"""Create a SARIF Fix object from ShellCheck fix data."""
		if not fix_data:
			return None
		return sarif.Fix(
			description=sarif.Message(
				text=fix_data.get('replacements', [{}])[0].get('replacement', '')
			),
			artifact_changes=[
				sarif.ArtifactChange(
					artifact_location=sarif.ArtifactLocation(
						uri=fix_data.get('file', '') if fix_data.get('file', '') else file
					),
					replacements=[
						sarif.Replacement(
							deleted_region=sarif.Region(
								start_line=fix_data.get('line', 0),
								start_column=fix_data.get('column', 0),
								end_line=fix_data.get('endLine', fix_data.get('line', 0)),
								end_column=fix_data.get('endColumn', fix_data.get('column', 0))
							),
							inserted_content=sarif.ArtifactContent(
								text=repl.get('replacement', '')
							)
						) for repl in fix_data.get('replacements', [])
					]
				)
			]
		)

	def convert_to_sarif(self, shellcheck_results):
		"""Convert shellcheck JSON results to SARIF format using sarif-om."""
		sarif_log = sarif.SarifLog(
			version="2.1.0",
			schema_uri=self.SARIF_SCHEMA_URL,
			runs=[
				sarif.Run(
					tool=sarif.Tool(
						driver=sarif.ToolComponent(
							name="ShellCheck",
							version="0.7.2",  # Update to your ShellCheck version
							information_uri="https://www.shellcheck.net/",
							rules=[]
						)
					),
					artifacts=[],
					results=[],
					default_source_language=self.SHELL_LANGUAGE_MAP.get(self.shell, "shell")
				)
			]
		)

		run = sarif_log.runs[0]
		driver = run.tool.driver
		rule_ids = {}

		for entry in shellcheck_results.get('comments', []):
			try:
				_index_code = entry.get('code', None)
				code = f"SC{_index_code}"
				
				# Add unique rules to the driver
				if code not in rule_ids:
					# Fetch rule documentation
					rule_doc = self.fetch_rule_doc(code)
					
					rule = sarif.ReportingDescriptor(
						id=code,
						name=code,
						short_description=sarif.MultiformatMessageString(
							text=entry.get('message', '')
						),
						full_description=sarif.MultiformatMessageString(
							text=rule_doc if rule_doc else entry.get('message', '')
						),
						help_uri=f"https://www.shellcheck.net/wiki/{code}",
						help=sarif.MultiformatMessageString(
							text=rule_doc if rule_doc else entry.get('message', '')
						)
					)
					driver.rules.append(rule)
					rule_ids[code] = rule
					rule_index = _index_code

				# Create the result object
				result = sarif.Result(
					rule_id=code,
					message=sarif.Message(
						text=entry.get('message', '')
					),
					locations=[
						sarif.Location(
							physical_location=sarif.PhysicalLocation(
								artifact_location=sarif.ArtifactLocation(
									uri=entry.get('file', '')
								),
								region=sarif.Region(
									start_line=entry.get('line', 0),
									start_column=entry.get('column', 0),
									end_line=entry.get('endLine', entry.get('line', 0)),
									end_column=entry.get('endColumn', entry.get('column', 0)),
									source_language=self.SHELL_LANGUAGE_MAP.get(self.shell, "shell")
								)
							)
						)
					],
				)

				# Add fixes if available
				if "fix" in entry:
					result.fixes = [self.create_fix(entry.get('file', ''), entry.get('fix', None))]

				run.results.append(result)
				run.artifacts.append(sarif.ArtifactLocation(
					uri=entry.get('file', '') if entry.get('file', '') else self.FILES
					))

			except Exception as e:
				print(f"::warning file={__file__},title='Error processing entry'::Details - {e}")
				print(entry)

		return sarif_log

	def write_sarif(self, file: str, sarif_log: sarif.SarifLog):
		"""Write the SARIF log to a file."""
		if not file:
			file = "shellcheck.sarif"
		with open(file, "w") as sarif_file:
			try:
				# Use serialize() method from sarif-om
				sarif_json = json.dumps(json.loads(json.dumps(sarif_log, default=lambda o: o.__dict__)), indent=2)
				sarif_file.write(sarif_json)
			except Exception as e:
				print("-"*20)
				print(sarif_log)
				print("-"*20)
				print(f"::error file={__file__},title='Error serializing {file}':: {e}")
				raise RuntimeError(f"Could not produce output JSON: {e}") from e

def main():
	parser = argparse.ArgumentParser(description="Run ShellCheck and output results in SARIF format.")
	parser.add_argument('--shell', choices=['bash', 'sh', 'dash', 'ksh', 'busybox'],
		default='bash', required=False, help="Specify the shell type.")
	parser.add_argument('--severity', choices=['error', 'warning', 'info', 'style'],
		default='style', help="Specify the severity level.")
	parser.add_argument('--output', default="shellcheck.sarif",
		help="Specify the output SARIF file name.")
	parser.add_argument('FILES', nargs='+', help="One or more files or glob patterns to check.")

	args = parser.parse_args()

	cli_tool = ShellCheckCLI(args.shell, args.severity, args.FILES)
	shellcheck_results = cli_tool.run_shellcheck()
	sarif_log = cli_tool.convert_to_sarif(shellcheck_results)
	cli_tool.write_sarif(args.output, sarif_log)

if __name__ == "__main__":
	main()
