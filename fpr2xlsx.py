#!/usr/bin/env python
import xml.etree.ElementTree as ET
from enum import Enum
from zipfile import ZipFile
from os import path,remove
from re import sub
import argparse

try:
	from xlsxwriter.workbook import Workbook
except ImportError:
	print("You should install xlsxwriter library, before using this script.")


class Severity(Enum):
	LOW = 1
	MEDIUM = 2
	HIGH = 3
	CRITICAL = 4

	
class Rule:
	def __init__(self, ruleId, probability, accuracy, impact):
		self.probability = float(probability)
		self.ruleId = ruleId
		self.accuracy = float(accuracy)
		self.impact = float(impact)
	
	def calculateSeverity(self, confidence):
		likelihood = (self.accuracy * self.probability * confidence)/25
		if self.impact >= 2.5:
			if likelihood >= 2.5:
				return Severity.CRITICAL
			else:
				return Severity.HIGH
		else:
			if likelihood >= 2.5:
				return Severity.MEDIUM
			else:
				return Severity.LOW
		
	def getRuleId(self):
		return self.ruleId

		
class Finding:
	def __init__(self, kingdom, category, filename, severity, function="", line = 1):
		self.kingdom = kingdom
		self.category = category
		self.filename = filename
		self.severity = severity
		self.function = function
		self.line = line
		
	def getSeverity(self):
		return self.severity.value
		
	def getKingdom(self):
		return self.kingdom
		

class FPR:
	def __init__(self, fprFile):
		self.fprFile = fprFile
		self.rules = []
		self.findings = []
				
	def getFindings(self):
		return self.findings
		
	def getRules(self):
		return self.rules
		
	def extractFVDL(self):
		zip = ZipFile(self.fprFile, 'r')
		try:
			zip.extract('audit.fvdl')
		except KeyError:
			zip.close()
			print("Malformed FPR file")
		zip.close()
	
	
	def processFVDL(self):
		if not path.exists('audit.fvdl'):
			print("Cannot perform the action, FVDL file is not found.")
			return false
		with open('audit.fvdl') as f:
			xmlstring = f.read()
		xmlstring = sub('\\sxmlns="[^"]+"', '', xmlstring, count=1)
		self.root = ET.fromstring(xmlstring)
	
	
	def extractRules(self):
		ruls = self.root.findall('EngineData/RuleInfo/Rule')
		
		for rul in ruls:
			ruleId = rul.attrib['id']
			groups = rul.findall('MetaInfo/Group')
			accuracy = 0.0
			impact = 0.0
			probability = 0.0
			for group in groups:
				if group.attrib['name'] == 'Accuracy':
					accuracy = float(group.text)
				elif group.attrib['name'] == 'Impact':
					impact = float(group.text)
				elif group.attrib['name'] == 'Probability':
					probability = group.text
			rule = Rule(ruleId, probability, accuracy, impact)
			self.rules.append(rule)
		
		
	def extractFindings(self):
		vulns = self.root.findall('Vulnerabilities/Vulnerability')
		for vuln in vulns:
			kingdom = vuln.find('ClassInfo/Kingdom').text
			category = vuln.find('ClassInfo/Type').text
			if(vuln.find('ClassInfo/Subtype') != None):
				category = category + ': ' + vuln.find('ClassInfo/Subtype').text
			if(vuln.find('AnalysisInfo/Unified/Context/Function') != None):
				filename = vuln.find('AnalysisInfo/Unified/Context/FunctionDeclarationSourceLocation').attrib['path']
				function = vuln.find('AnalysisInfo/Unified/Context/Function').attrib['name']
				line = vuln.find('AnalysisInfo/Unified/Context/FunctionDeclarationSourceLocation').attrib['line']
			else:
				filename = vuln.find('AnalysisInfo/Unified/Trace/Primary/Entry/Node/SourceLocation').attrib['path']
				line = vuln.find('AnalysisInfo/Unified/Trace/Primary/Entry/Node/SourceLocation').attrib['line']
				function = ""
			classId = vuln.find('ClassInfo/ClassID').text
			confidence = float(vuln.find('InstanceInfo/Confidence').text)
			severity = Severity.LOW
			self.extractRules()
			for rule in self.rules:
				if rule.getRuleId() == classId:
					severity = rule.calculateSeverity(confidence)
					break
			finding = Finding(kingdom, category, filename, severity, function, line)
			self.findings.append(finding)


class ReportWriter:
	def writeWorksheet(self, workbook, name):
		fs = self.orderFindings(name)
		if len(fs) > 0:
			worksheet = workbook.add_worksheet(name)
			colNames = ['Risk Level', 'Kingdom', 'Category', 'File Path', 'Funtion', 'Line Number']
			headerCF = self.generateCellFormat(workbook, True, 'white', 'blue')
			self.addColumnNames(worksheet, colNames, headerCF)
			criticalCF = self.generateCellFormat(workbook, True, 'white', '#8A0808')
			highCF = self.generateCellFormat(workbook, True, 'white', '#FF0000')
			mediumCF = self.generateCellFormat(workbook, True, 'white', 'orange')
			lowCF = self.generateCellFormat(workbook, True, 'white', '#A4A4A4')
			formats = [lowCF, mediumCF, highCF, criticalCF]
			self.resizeWorksheet(worksheet, fs)
			i = 2
			for f in fs:
				cf = workbook.add_format({'border':1})
				worksheet.write("A" + str(i), f.severity.name.upper(), formats[f.severity.value - 1])
				worksheet.write("B" + str(i), f.kingdom, cf)
				worksheet.write("C" + str(i), f.category, cf)
				worksheet.write("D" + str(i), f.filename, cf)
				worksheet.write("E" + str(i), f.function, cf)
				worksheet.write("F" + str(i), f.line, cf)
				i = i + 1
			worksheet.autofilter('A1:F' + str(len(fs)))
	
	
	def resizeWorksheet(self, worksheet, fs):
		kl = len('Kingdom')
		cl = len('Category')
		ful = len('Function')
		fil = len('File Path')
		for f in fs:
			kl = max(kl, len(f.kingdom))
			cl = max(cl, len(f.category))
			ful = max(ful, len(f.function))
			fil = max(fil, len(f.filename))
		sl = len('Risk Level')
		ll = len('Line Number')
		worksheet.set_column('A:A', sl)
		worksheet.set_column('B:B', kl)
		worksheet.set_column('C:C', cl)
		worksheet.set_column('D:D', fil)
		worksheet.set_column('E:E', ful)
		worksheet.set_column('F:F', ll)
	
	
	def writeToExcel(self, findings, filename):
		self.findings = findings
		workbook = Workbook(filename)
		self.writeWorksheet(workbook, 'all')
		self.writeWorksheet(workbook, 'critical')
		self.writeWorksheet(workbook, 'high')
		self.writeWorksheet(workbook, 'medium')
		self.writeWorksheet(workbook, 'low')
		workbook.close()
		
		
	def addColumnNames(self, worksheet, colNames, cell_format):
		for i in range(0, len(colNames)):
			worksheet.write(chr(ord('A') + i) + '1', colNames[i], cell_format)
	
	
	def generateCellFormat(self, workbook, bold=False, fgcolor='black', bgcolor='white'):
		cell_format = workbook.add_format({'border':1})
		if bold:
			cell_format.set_bold()
		cell_format.set_font_color(fgcolor)
		cell_format.set_bg_color(bgcolor)
		return cell_format
	
	
	def orderFindings(self, severity):
		if severity == 'critical':
			fs = list(filter(lambda x: x.severity.value == 4, self.findings))
			fs = sorted(fs, key=lambda x: x.category)
			return fs
		elif severity == 'high':
			fs = list(filter(lambda x: x.severity.value == 3, self.findings))
			fs = sorted(fs, key=lambda x: x.category)
			return fs
		elif severity == 'medium':
			fs = list(filter(lambda x: x.severity.value == 2, self.findings))
			fs = sorted(fs, key=lambda x: x.category)
			return fs
		elif severity == 'low':
			fs = list(filter(lambda x: x.severity.value == 1, self.findings))
			fs = sorted(fs, key=lambda x: x.category)
			return fs
		else:
			fs = sorted(self.findings, key=lambda x: ((-1*x.severity.value), x.category))
			return fs



def main(args):
	fprfilename = args.input
	fpr = FPR(args.input)
	fpr.extractFVDL()
	fpr.processFVDL()
	fpr.extractFindings()
	findings = fpr.getFindings()
	writer = ReportWriter()
	writer.writeToExcel(findings, fprfilename.replace('.fpr','.xlsx'))
	remove('audit.fvdl')
	
if __name__ == '__main__':
	parser = argparse.ArgumentParser(description = 'This tool converts Fortify FPR reports to Excel reports.')
	parser.add_argument('--input', '-i',
		help='input Fortify .fpr report',
		dest='input',
		required=True,
	)
	args = parser.parse_args()
	if path.exists(args.input) and path.isfile(args.input):
		main(args)
	else:
		print("Could find the FPR file.")
	
