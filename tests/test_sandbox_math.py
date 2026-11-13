import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import sandbox_math  # noqa: E402


class AddTests(unittest.TestCase):
    def test_add(self):
        self.assertEqual(sandbox_math.add(2, 3), 5)


if __name__ == "__main__":
    unittest.main()
