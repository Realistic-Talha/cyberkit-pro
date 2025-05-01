import unittest
from tools.log_analyzer import LogAnalyzer

class TestLogAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = LogAnalyzer()
        self.sample_log = """
[2024-01-28 01:23:45] INFO: System startup
[2024-01-28 01:24:00] ERROR: Failed login attempt from IP 192.168.1.100
[2024-01-28 01:24:15] WARNING: Suspicious activity detected
[2024-01-28 01:24:30] ERROR: Database connection failed
""".strip()

    def test_basic_analysis(self):
        result = self.analyzer.analyze_log(self.sample_log)
        self.assertEqual(result['total_lines'], 4)
        self.assertTrue(len(result['patterns_found']['error']) > 0)
        
    def test_error_detection(self):
        result = self.analyzer.analyze_log(self.sample_log)
        errors = result['patterns_found']['error']
        self.assertIn('Failed login attempt', ' '.join(errors))
        self.assertIn('Database connection failed', ' '.join(errors))

    def test_timeline_creation(self):
        result = self.analyzer.analyze_log(self.sample_log)
        timeline = result['timeline']
        self.assertEqual(len(timeline), 4)
        self.assertTrue(all('timestamp' in entry for entry in timeline))

if __name__ == '__main__':
    unittest.main()
