import sqlite3
import json
from datetime import datetime

def init_db():
    """Initialize database"""
    conn = sqlite3.connect('seccheck.db')
    c = conn.cursor()
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            score INTEGER,
            grade TEXT,
            scan_date TIMESTAMP,
            results TEXT,
            user_ip TEXT
        )
    ''')
    
    c.execute('''
        CREATE INDEX IF NOT EXISTS idx_domain ON scans(domain)
    ''')
    
    c.execute('''
        CREATE INDEX IF NOT EXISTS idx_date ON scans(scan_date DESC)
    ''')
    
    conn.commit()
    conn.close()


def save_scan(domain, results, user_ip=None):
    """Save scan to database"""
    conn = sqlite3.connect('seccheck.db')
    c = conn.cursor()
    
    c.execute('''
        INSERT INTO scans (domain, score, grade, scan_date, results, user_ip)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (
        domain,
        results['score']['score'],
        results['score']['grade'],
        datetime.now(),
        json.dumps(results),
        user_ip
    ))
    
    conn.commit()
    scan_id = c.lastrowid
    conn.close()
    
    return scan_id


def get_scan_history(domain, limit=10):
    """Get scan history for a domain"""
    conn = sqlite3.connect('seccheck.db')
    c = conn.cursor()
    
    c.execute('''
        SELECT id, score, grade, scan_date
        FROM scans
        WHERE domain = ?
        ORDER BY scan_date DESC
        LIMIT ?
    ''', (domain, limit))
    
    rows = c.fetchall()
    conn.close()
    
    history = []
    for row in rows:
        history.append({
            'id': row[0],
            'score': row[1],
            'grade': row[2],
            'date': row[3]
        })
    
    return history


def get_recent_scans(limit=50):
    """Get recent scans across all domains"""
    conn = sqlite3.connect('seccheck.db')
    c = conn.cursor()
    
    c.execute('''
        SELECT domain, score, grade, scan_date
        FROM scans
        ORDER BY scan_date DESC
        LIMIT ?
    ''', (limit,))
    
    rows = c.fetchall()
    conn.close()
    
    scans = []
    for row in rows:
        scans.append({
            'domain': row[0],
            'score': row[1],
            'grade': row[2],
            'date': row[3]
        })
    
    return scans

def get_scan_by_id(scan_id):
    """Get a specific scan by ID"""
    conn = sqlite3.connect('seccheck.db')
    conn.row_factory = sqlite3.Row  # Return rows as dictionaries
    c = conn.cursor()
    
    c.execute('''
        SELECT id, domain, score, grade, scan_date, results, user_ip
        FROM scans
        WHERE id = ?
    ''', (scan_id,))
    
    row = c.fetchone()
    conn.close()
    
    if row:
        return dict(row)
    return None

def get_all_scans_grouped(limit=50):
    """Get recent scans grouped by domain with latest + average scores"""
    conn = sqlite3.connect('seccheck.db')
    c = conn.cursor()
    
    c.execute('''
        SELECT s1.domain, 
               COUNT(*) as scan_count, 
               MAX(s1.scan_date) as last_scan,
               (SELECT score FROM scans s2 WHERE s2.domain = s1.domain ORDER BY scan_date DESC LIMIT 1) as latest_score,
               AVG(s1.score) as avg_score,
               MIN(s1.score) as min_score, 
               MAX(s1.score) as max_score
        FROM scans s1
        GROUP BY s1.domain
        ORDER BY last_scan DESC
        LIMIT ?
    ''', (limit,))
    
    rows = c.fetchall()
    conn.close()
    
    domains = []
    for row in rows:
        domains.append({
            'domain': row[0],
            'scan_count': row[1],
            'last_scan': row[2],
            'latest_score': row[3] if row[3] else 0,
            'avg_score': round(row[4], 1) if row[4] else 0,
            'min_score': row[5],
            'max_score': row[6]
        })
    
    return domains

def get_domain_scans(domain, limit=20):
    """Get all scans for a specific domain"""
    conn = sqlite3.connect('seccheck.db')
    c = conn.cursor()
    
    c.execute('''
        SELECT id, score, grade, scan_date
        FROM scans
        WHERE domain = ?
        ORDER BY scan_date DESC
        LIMIT ?
    ''', (domain, limit))
    
    rows = c.fetchall()
    conn.close()
    
    scans = []
    for row in rows:
        scans.append({
            'id': row[0],
            'score': row[1],
            'grade': row[2],
            'date': row[3]
        })
    
    return scans