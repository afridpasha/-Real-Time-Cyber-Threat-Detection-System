from flask import Flask, render_template, jsonify, request
import threading
import time
import json
from datetime import datetime
from threat_detection_system import RealTimeThreatDetector, NetworkPacket, generate_sample_packets
import logging
import csv
import io
from datetime import datetime, timedelta

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'

# Global threat detector instance
threat_detector = RealTimeThreatDetector()
monitoring_active = False

@app.route('/')
def dashboard():
    """Main dashboard page"""
    return render_template('dashboard.html')

@app.route('/api/threats')
def get_threats():
    """API endpoint to get current threats"""
    return jsonify(threat_detector.get_threat_summary())

@app.route('/api/start-monitoring', methods=['POST'])
def start_monitoring():
    """Start real-time monitoring"""
    global monitoring_active
    monitoring_active = True
    
    # Start monitoring in background thread
    monitoring_thread = threading.Thread(target=real_time_monitoring)
    monitoring_thread.daemon = True
    monitoring_thread.start()
    
    return jsonify({'status': 'monitoring_started'})

@app.route('/api/stop-monitoring', methods=['POST'])
def stop_monitoring():
    """Stop real-time monitoring"""
    global monitoring_active
    monitoring_active = False
    return jsonify({'status': 'monitoring_stopped'})

@app.route('/api/system-stats')
def system_stats():
    """Get system statistics"""
    return jsonify(threat_detector.get_system_stats())

@app.route('/api/latest-threats')
def latest_threats():
    """Get latest threats for real-time updates"""
    summary = threat_detector.get_threat_summary()
    return jsonify({
        'threats': summary.get('recent_threats', [])[-10:],
        'stats': threat_detector.get_system_stats(),
        'summary': summary
    })

@app.route('/api/threat-intelligence/<ip>')
def get_threat_intelligence(ip):
    """Get detailed threat intelligence for an IP"""
    intel = threat_detector.get_threat_intelligence(ip)
    return jsonify(intel)

@app.route('/api/security-recommendations')
def get_security_recommendations():
    """Get personalized security recommendations"""
    recommendations = threat_detector.generate_security_recommendations()
    return jsonify(recommendations)

@app.route('/api/export-report')
def export_threat_report():
    """Export threat report as CSV"""
    summary = threat_detector.get_threat_summary()
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write headers
    writer.writerow(['Timestamp', 'Threat Type', 'Severity', 'Source IP', 'Target IP', 'Protocol', 'Action Taken'])
    
    # Write threat data
    for threat in summary.get('recent_threats', []):
        writer.writerow([
            threat['timestamp'],
            threat['type'],
            threat['threat_level'],
            threat['source_ip'],
            threat['destination_ip'],
            threat['protocol'],
            threat['response_action']
        ])
    
    output.seek(0)
    return app.response_class(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=threat_report.csv'}
    )

@app.route('/api/incident-response')
def get_incident_response():
    """Get incident response playbook"""
    playbook = threat_detector.get_incident_response_playbook()
    return jsonify(playbook)

@app.route('/api/network-map')
def get_network_map():
    """Get network topology and threat visualization"""
    network_data = threat_detector.generate_network_map()
    return jsonify(network_data)

@app.route('/api/vulnerability-scan')
def vulnerability_scan():
    """Perform vulnerability assessment"""
    vulnerabilities = threat_detector.scan_vulnerabilities()
    return jsonify(vulnerabilities)

@app.route('/api/threat-prediction')
def threat_prediction():
    """Get AI-powered threat predictions"""
    predictions = threat_detector.predict_future_threats()
    return jsonify(predictions)

def real_time_monitoring():
    """Enhanced background thread for real-time threat detection"""
    while monitoring_active:
        try:
            # Generate sample network packets with enhanced variety
            packets = generate_sample_packets(8)
            
            for packet in packets:
                threat = threat_detector.detect_threat(packet)
                if threat:
                    # Log high-priority threats
                    if threat.threat_level in ['High', 'Critical']:
                        logging.warning(f"High-priority threat detected: {threat.type}")
                        # Auto-generate incident response
                        threat_detector.trigger_incident_response(threat)
            
            # Perform periodic security scans
            if threat_detector.events_processed % 50 == 0:
                threat_detector.update_threat_intelligence()
            
            time.sleep(2)  # Check every 2 seconds
            
        except Exception as e:
            logging.error(f"Error in monitoring: {e}")
            time.sleep(5)

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    app.run(debug=True, host='0.0.0.0', port=5000)