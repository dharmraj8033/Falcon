"""
Results Exporter
Handles exporting scan results to various formats
"""

import json
import csv
import asyncio
from typing import Dict, List, Any, Optional
from pathlib import Path
from datetime import datetime
from rich.console import Console

console = Console()

class ResultExporter:
    """Export scan results to various formats"""
    
    def __init__(self, config):
        self.config = config
        self.output_dir = Path(config.get('general.output_dir', './output'))
        self.output_dir.mkdir(exist_ok=True)
    
    async def export(self, results: Dict[str, Any], format_type: str, output_path: Optional[str] = None):
        """Export results to specified format"""
        
        if not output_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"falcon_scan_{timestamp}.{format_type}"
            output_path = self.output_dir / filename
        
        export_methods = {
            'json': self._export_json,
            'html': self._export_html,
            'csv': self._export_csv,
            'pdf': self._export_pdf,
            'xml': self._export_xml
        }
        
        if format_type in export_methods:
            await export_methods[format_type](results, output_path)
            console.print(f"[green]✅ Results exported to {output_path}[/green]")
        else:
            console.print(f"[red]❌ Unsupported export format: {format_type}[/red]")
    
    async def _export_json(self, results: Dict[str, Any], output_path: Path):
        """Export to JSON format"""
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False, default=str)
    
    async def _export_html(self, results: Dict[str, Any], output_path: Path):
        """Export to HTML format"""
        
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Falcon Security Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; }}
        .summary {{ background: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .vulnerability {{ background: white; padding: 20px; margin-bottom: 15px; border-radius: 10px; border-left: 5px solid #e74c3c; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .vulnerability.critical {{ border-left-color: #8b0000; }}
        .vulnerability.high {{ border-left-color: #e74c3c; }}
        .vulnerability.medium {{ border-left-color: #f39c12; }}
        .vulnerability.low {{ border-left-color: #3498db; }}
        .vulnerability.info {{ border-left-color: #95a5a6; }}
        .severity {{ display: inline-block; padding: 5px 10px; border-radius: 5px; color: white; font-weight: bold; }}
        .severity.critical {{ background-color: #8b0000; }}
        .severity.high {{ background-color: #e74c3c; }}
        .severity.medium {{ background-color: #f39c12; }}
        .severity.low {{ background-color: #3498db; }}
        .severity.info {{ background-color: #95a5a6; }}
        .tech-stack {{ background: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .tech-item {{ display: inline-block; background: #ecf0f1; padding: 8px 12px; margin: 5px; border-radius: 5px; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 20px; }}
        .stat-box {{ background: white; padding: 20px; border-radius: 10px; text-align: center; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .stat-number {{ font-size: 2em; font-weight: bold; color: #3498db; }}
        .code {{ background: #2c3e50; color: #ecf0f1; padding: 15px; border-radius: 5px; font-family: monospace; overflow-x: auto; }}
        h1, h2, h3 {{ color: #2c3e50; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🦅 Falcon Security Scan Report</h1>
        <p><strong>Target:</strong> {target}</p>
        <p><strong>Scan Date:</strong> {scan_date}</p>
        <p><strong>Falcon Version:</strong> {version}</p>
    </div>
    
    <div class="stats">
        <div class="stat-box">
            <div class="stat-number">{vuln_count}</div>
            <div>Vulnerabilities Found</div>
        </div>
        <div class="stat-box">
            <div class="stat-number">{tech_count}</div>
            <div>Technologies Detected</div>
        </div>
        <div class="stat-box">
            <div class="stat-number">{url_count}</div>
            <div>URLs Crawled</div>
        </div>
        <div class="stat-box">
            <div class="stat-number">{param_count}</div>
            <div>Parameters Found</div>
        </div>
    </div>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <p>This security assessment was performed using Falcon AI-Enhanced Vulnerability Scanner. 
        The scan identified <strong>{vuln_count} vulnerabilities</strong> across the target application.</p>
        
        <h3>Risk Distribution</h3>
        <ul>
            <li>Critical: {critical_count}</li>
            <li>High: {high_count}</li>
            <li>Medium: {medium_count}</li>
            <li>Low: {low_count}</li>
            <li>Info: {info_count}</li>
        </ul>
    </div>
    
    {tech_section}
    
    <div class="vulnerabilities">
        <h2>Vulnerability Details</h2>
        {vulnerabilities}
    </div>
    
    <div class="summary">
        <h2>Scan Statistics</h2>
        <ul>
            <li><strong>Scan Duration:</strong> {scan_duration:.2f} seconds</li>
            <li><strong>Total Requests:</strong> {total_requests}</li>
            <li><strong>AI Analysis:</strong> {ai_analysis}</li>
        </ul>
    </div>
    
    <div class="summary">
        <p><em>Report generated by Falcon AI-Enhanced Vulnerability Scanner v{version}</em></p>
        <p><em>For more information, visit: https://github.com/dharmraj8033/Falcon</em></p>
    </div>
</body>
</html>
        """
        
        # Prepare data for template
        vulnerabilities = results.get('vulnerabilities', [])
        technologies = results.get('technologies', {})
        stats = results.get('stats', {})
        
        # Count vulnerabilities by severity
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'info').lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Generate vulnerability HTML
        vuln_html = ""
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'INFO').lower()
            vuln_html += f"""
            <div class="vulnerability {severity}">
                <h3>{vuln.get('type', 'Unknown')} <span class="severity {severity}">{vuln.get('severity', 'INFO')}</span></h3>
                <p><strong>URL:</strong> <code>{vuln.get('url', 'N/A')}</code></p>
                <p><strong>Parameter:</strong> <code>{vuln.get('parameter', 'N/A')}</code></p>
                <p><strong>Description:</strong> {vuln.get('description', 'No description')}</p>
                <p><strong>Impact:</strong> {vuln.get('impact', 'No impact description')}</p>
                <p><strong>Recommendation:</strong> {vuln.get('recommendation', 'No recommendation')}</p>
                {f'<p><strong>Evidence:</strong></p><div class="code">{vuln.get("evidence", "")}</div>' if vuln.get('evidence') else ''}
                {f'<p><strong>AI Analysis:</strong> {vuln.get("ai_explanation", "")}</p>' if vuln.get('ai_explanation') else ''}
            </div>
            """
        
        # Generate technology stack HTML
        tech_html = ""
        if technologies:
            tech_html = """
            <div class="tech-stack">
                <h2>Detected Technologies</h2>
            """
            for category, techs in technologies.items():
                if techs:
                    tech_html += f"<h3>{category.replace('_', ' ').title()}</h3>"
                    for tech_name, tech_info in techs.items():
                        version = tech_info.get('version', '')
                        confidence = tech_info.get('confidence', 0) * 100
                        tech_html += f'<div class="tech-item">{tech_name} {version} ({confidence:.1f}%)</div>'
            tech_html += "</div>"
        
        # Fill template
        html_content = html_template.format(
            target=results.get('target', 'Unknown'),
            scan_date=datetime.fromtimestamp(results.get('timestamp', 0)).strftime('%Y-%m-%d %H:%M:%S'),
            version=results.get('falcon_version', '1.0.0'),
            vuln_count=len(vulnerabilities),
            tech_count=sum(len(techs) for techs in technologies.values()),
            url_count=stats.get('urls_crawled', 0),
            param_count=stats.get('parameters_found', 0),
            critical_count=severity_counts['critical'],
            high_count=severity_counts['high'],
            medium_count=severity_counts['medium'],
            low_count=severity_counts['low'],
            info_count=severity_counts['info'],
            tech_section=tech_html,
            vulnerabilities=vuln_html,
            scan_duration=stats.get('scan_duration', 0),
            total_requests=stats.get('total_requests', 0),
            ai_analysis='Enabled' if results.get('ai_analysis') else 'Disabled'
        )
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
    
    async def _export_csv(self, results: Dict[str, Any], output_path: Path):
        """Export to CSV format"""
        
        vulnerabilities = results.get('vulnerabilities', [])
        
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Header
            writer.writerow([
                'Type', 'Severity', 'URL', 'Parameter', 'Description',
                'Impact', 'Recommendation', 'Evidence', 'AI Confidence'
            ])
            
            # Vulnerability data
            for vuln in vulnerabilities:
                writer.writerow([
                    vuln.get('type', ''),
                    vuln.get('severity', ''),
                    vuln.get('url', ''),
                    vuln.get('parameter', ''),
                    vuln.get('description', ''),
                    vuln.get('impact', ''),
                    vuln.get('recommendation', ''),
                    vuln.get('evidence', ''),
                    vuln.get('ai_confidence', '')
                ])
    
    async def _export_pdf(self, results: Dict[str, Any], output_path: Path):
        """Export to PDF format"""
        
        try:
            # First create HTML, then convert to PDF
            html_path = output_path.with_suffix('.html')
            await self._export_html(results, html_path)
            
            # Try to convert HTML to PDF using weasyprint
            try:
                from weasyprint import HTML
                HTML(filename=str(html_path)).write_pdf(str(output_path))
                html_path.unlink()  # Remove temporary HTML file
            except ImportError:
                console.print("[yellow]⚠️  WeasyPrint not available, creating PDF report as HTML[/yellow]")
                # Rename HTML file to PDF extension for now
                html_path.rename(output_path.with_suffix('.html'))
        
        except Exception as e:
            console.print(f"[red]❌ PDF export failed: {e}[/red]")
    
    async def _export_xml(self, results: Dict[str, Any], output_path: Path):
        """Export to XML format"""
        
        xml_content = '<?xml version="1.0" encoding="UTF-8"?>\n'
        xml_content += '<falcon_scan_report>\n'
        xml_content += f'  <metadata>\n'
        xml_content += f'    <target>{results.get("target", "")}</target>\n'
        xml_content += f'    <timestamp>{results.get("timestamp", "")}</timestamp>\n'
        xml_content += f'    <version>{results.get("falcon_version", "")}</version>\n'
        xml_content += f'  </metadata>\n'
        
        # Vulnerabilities
        xml_content += '  <vulnerabilities>\n'
        for vuln in results.get('vulnerabilities', []):
            xml_content += '    <vulnerability>\n'
            xml_content += f'      <type><![CDATA[{vuln.get("type", "")}]]></type>\n'
            xml_content += f'      <severity>{vuln.get("severity", "")}</severity>\n'
            xml_content += f'      <url><![CDATA[{vuln.get("url", "")}]]></url>\n'
            xml_content += f'      <parameter>{vuln.get("parameter", "")}</parameter>\n'
            xml_content += f'      <description><![CDATA[{vuln.get("description", "")}]]></description>\n'
            xml_content += f'      <impact><![CDATA[{vuln.get("impact", "")}]]></impact>\n'
            xml_content += f'      <recommendation><![CDATA[{vuln.get("recommendation", "")}]]></recommendation>\n'
            xml_content += '    </vulnerability>\n'
        xml_content += '  </vulnerabilities>\n'
        
        # Technologies
        xml_content += '  <technologies>\n'
        for category, techs in results.get('technologies', {}).items():
            xml_content += f'    <category name="{category}">\n'
            for tech_name, tech_info in techs.items():
                xml_content += f'      <technology>\n'
                xml_content += f'        <name>{tech_name}</name>\n'
                xml_content += f'        <version>{tech_info.get("version", "")}</version>\n'
                xml_content += f'        <confidence>{tech_info.get("confidence", 0)}</confidence>\n'
                xml_content += f'      </technology>\n'
            xml_content += f'    </category>\n'
        xml_content += '  </technologies>\n'
        
        xml_content += '</falcon_scan_report>\n'
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(xml_content)
