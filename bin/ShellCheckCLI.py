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
import sarif_om as sarif

class ShellCheckCLI:
	def __init__(self, shell, severity, files):
		self.shell = shell
		self.severity = severity
		self.files = files

	def run_shellcheck(self):
		"""Run shellcheck with the specified arguments and return the JSON output."""
		command = [
			'shellcheck', f'--shell={self.shell}', f'--severity={self.severity}', '--format=json1'
		] + self.files
		try:
			result = subprocess.run(command, capture_output=True, text=True, check=True)
			return json.loads(result.stdout)
		except subprocess.CalledProcessError as e:
			print(f"::error file={__file__},title='Error running shellcheck':: {e}")
			return []

	def convert_to_sarif(self, shellcheck_results):
		"""Convert shellcheck JSON results to SARIF format using sarif-om."""
		# Initialize the SARIF log
		sarif_log = sarif.SarifLog(
			version="2.1.0",
			runs=[
				sarif.Run(
					tool=sarif.Tool(
						driver=sarif.ToolComponent(
							name="ShellCheck",
							version="0.7.2",  # Update to your ShellCheck version
							informationUri="https://www.shellcheck.net/",
							rules=[]
						)
					),
					results=[]
				)
			]
		)

		run = sarif_log.runs[0]
		driver = run.tool.driver

		# Map to track unique rules
		rule_ids = {}

		for entry in shellcheck_results:
			code = f"SC{entry['code']}"  # Prefix with 'SC' to match ShellCheck codes
			# Add unique rules to the driver
			if code not in rule_ids:
				rule = sarif.ReportingDescriptor(
					id=code,
					name=code,
					shortDescription=sarif.MultiformatMessageString(
						text=entry.get('message', '')
					),
					helpUri=f"https://www.shellcheck.net/wiki/{code}"
				)
				driver.rules.append(rule)
				rule_ids[code] = rule

			# Create the result object
			result = sarif.Result(
				ruleId=code,
				message=sarif.Message(
					text=entry.get('message', '')
				),
				locations=[
					sarif.Location(
						physicalLocation=sarif.PhysicalLocation(
							artifactLocation=sarif.ArtifactLocation(
								uri=entry.get('file', '')
							),
							region=sarif.Region(
								startLine=entry.get('line', 0),
								startColumn=entry.get('column', 0)
							)
						)
					)
				]
			)

			run.results.append(result)

		return sarif_log

	def write_sarif(self, file, sarif_log):
		"""Write the SARIF log to a file."""
		if not file:
			file = "shellcheck.sarif"
		with open(file, "w") as sarif_file:
			json.dump(sarif_log.to_dict(), sarif_file, indent=2)

def main():
	parser = argparse.ArgumentParser(description="Run ShellCheck and output results in SARIF format.")
	parser.add_argument('--shell', choices=['bash', 'sh', 'dash', 'ksh', 'busybox'], default='bash', help='Specify the shell type.')
	parser.add_argument('--severity', choices=['error', 'warning', 'info', 'style'], default='style', help='Specify the severity level.')
	parser.add_argument('--output', default='shellcheck.sarif', help='Specify the output SARIF file name.')
	parser.add_argument('FILES', nargs='+', help='One or more files or glob patterns to check.')

	args = parser.parse_args()

	cli_tool = ShellCheckCLI(args.shell, args.severity, args.FILES)
	shellcheck_results = cli_tool.run_shellcheck()
	sarif_log = cli_tool.convert_to_sarif(shellcheck_results)
	cli_tool.write_sarif(args.output, sarif_log)

if __name__ == "__main__":
	main()
