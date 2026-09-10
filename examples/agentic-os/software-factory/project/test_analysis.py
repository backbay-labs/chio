import os
import sys
import unittest
sys.path.insert(0, os.path.dirname(__file__))
from analysis import moving_average

class MovingAverageTests(unittest.TestCase):
    def test_only_complete_windows(self):
        self.assertEqual(moving_average([1, 2, 3, 4], 2), [1.5, 2.5, 3.5])
    def test_empty_input(self):
        self.assertEqual(moving_average([], 3), [])
    def test_window_larger_than_input(self):
        self.assertEqual(moving_average([5], 3), [])
    def test_invalid_window(self):
        for window in [0, -1]:
            with self.assertRaises(ValueError):
                moving_average([1, 2], window)
    def test_preserves_input(self):
        values = [2, 4, 6]
        self.assertEqual(moving_average(values, 1), [2, 4, 6])
        self.assertEqual(values, [2, 4, 6])

if __name__ == '__main__':
    unittest.main(verbosity=2)
