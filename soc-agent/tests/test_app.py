"""Prueba de humo de la interfaz Streamlit (se omite si Streamlit no está instalado)."""
import os
import unittest

try:
    from streamlit.testing.v1 import AppTest
except ImportError:  # pragma: no cover
    AppTest = None

RUTA_APP = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app.py")


@unittest.skipIf(AppTest is None, "streamlit no instalado")
class TestApp(unittest.TestCase):
    def test_app_carga_sin_errores_y_maneja_sensor_corrupto(self):
        at = AppTest.from_file(RUTA_APP, default_timeout=60).run()
        self.assertEqual(len(at.exception), 0)
        self.assertGreaterEqual(len(at.success), 1)  # hay una decisión visible
        corrupto = [c for c in at.checkbox if "corrupto" in c.label][0]
        corrupto.check().run()
        self.assertEqual(len(at.exception), 0)
        self.assertTrue(any("inválido" in e.value for e in at.error))


if __name__ == "__main__":
    unittest.main()
