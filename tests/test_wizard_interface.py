"""The displayed adapter rows and target fields match what the wizard accepts."""
import io
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tui import Console
import wizard


class WizardInterfaceTests(unittest.TestCase):
    def test_keyboard_checkboxes_toggle_and_continue(self):
        ui = Console(stream=io.StringIO(), no_color=True)
        ui.tty = True
        keys = iter([' ', '\x1b[B', '\r', '\x1b[B', '\r'])
        with patch.object(sys.stdin, 'isatty', return_value=True), patch.object(ui, '_read_key', side_effect=lambda: next(keys)):
            self.assertEqual(ui.choose_many('Adaptörler', [(35, 'Wi-Fi'), (117, 'WSL')]), [35, 117])

    def test_noninteractive_row_number_is_not_windows_index(self):
        ui = Console(stream=io.StringIO(), no_color=True)
        with patch.object(ui, 'prompt', return_value='2'):
            self.assertEqual(ui.choose_many('Adaptörler', [(35, 'Wi-Fi'), (117, 'WSL')]), [117])

    def test_enter_accepts_preselected_default_adapter(self):
        ui = Console(stream=io.StringIO(), no_color=True)
        ui.tty = True
        with patch.object(sys.stdin, 'isatty', return_value=True), patch.object(ui, '_read_key', return_value='\r'):
            self.assertEqual(ui.choose_many('Adaptörler', [(35, 'Wi-Fi'), (117, 'WSL')], defaults={35}), [35])

    def test_escape_cancels_menu_without_selecting_a_module(self):
        ui = Console(stream=io.StringIO(), no_color=True)
        ui.tty = True
        with patch.object(sys.stdin, 'isatty', return_value=True), patch.object(ui, '_read_key', return_value='\x1b'):
            with self.assertRaises(KeyboardInterrupt):
                ui.menu('AD', [('0', 'Atla'), ('2', 'Verilen DC')])

    def test_only_active_addressed_adapters_are_selectable(self):
        snapshot = {'adapters': [
            {'name': 'Wi-Fi', 'index': 35, 'status': 'Up', 'addresses': [{'address': '192.168.0.8'}]},
            {'name': 'Cato', 'index': 29, 'status': 'Up', 'addresses': [{'address': 'fe80::10'}]},
            {'name': 'Ethernet', 'index': 2, 'status': 'Disconnected', 'addresses': [{'address': '10.0.0.3'}]},
            {'name': 'vEthernet (WSL)', 'index': 117, 'status': 'Up', 'addresses': [{'address': '172.28.1.1'}]},
        ], 'default_routes': [{'destination': '0.0.0.0/0', 'interface_index': 35}]}
        self.assertEqual([item['index'] for item, _ in wizard.selectable_adapters(snapshot)], [35, 117])

    def test_numeric_and_domain_fields_reject_mixed_inputs(self):
        with patch.object(wizard.UI, 'prompt', side_effect=['example.com', '192.0.2.5, 192.0.2.0/28']):
            self.assertEqual(wizard.collect_scope_entries('IP/CIDR', 'numeric'),
                             ['192.0.2.5', '192.0.2.0/28'])
        with patch.object(wizard.UI, 'prompt', side_effect=['192.0.2.5', 'app.example.com;example.com']):
            self.assertEqual(wizard.collect_scope_entries('Domain/FQDN', 'named'),
                             ['app.example.com', 'example.com'])


if __name__ == '__main__':
    unittest.main()
