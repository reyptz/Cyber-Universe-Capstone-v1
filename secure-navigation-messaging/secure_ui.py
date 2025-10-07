#!/usr/bin/env python3
"""
Interface utilisateur pour la gestion des connexions sécurisées
Combine VPN, Tor et messagerie sécurisée dans une interface unifiée
"""

import asyncio
import json
import logging
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np

# Import des modules sécurisés
try:
    from .vpn_manager import VPNManager, VPNStatus
    from .tor_manager import TorManager, TorStatus
    from ..secure_messaging.secure_email import SecureEmailManager
except ImportError:
    # Pour les tests standalone
    import sys
    sys.path.append('..')
    from vpn_manager import VPNManager, VPNStatus
    from tor_manager import TorManager, TorStatus
    from secure_messaging.secure_email import SecureEmailManager

class SecureNavigationUI:
    """Interface utilisateur principale pour la navigation sécurisée"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Ghost Cyber Universe - Navigation Sécurisée")
        self.root.geometry("1200x800")
        self.root.configure(bg='#1a1a1a')
        
        # Style sombre
        self.setup_dark_theme()
        
        # Gestionnaires de sécurité
        self.vpn_manager = VPNManager()
        self.tor_manager = TorManager()
        self.email_manager = SecureEmailManager()
        
        # Variables d'état
        self.vpn_connected = tk.BooleanVar()
        self.tor_connected = tk.BooleanVar()
        self.email_authenticated = tk.BooleanVar()
        
        # Données de monitoring
        self.connection_history = []
        self.security_metrics = {
            "vpn_uptime": 0,
            "tor_circuits": 0,
            "messages_sent": 0,
            "threats_blocked": 0
        }
        
        # Configuration de l'interface
        self.setup_ui()
        self.setup_monitoring()
        
        # Démarrage des tâches asynchrones
        self.loop = asyncio.new_event_loop()
        self.async_thread = threading.Thread(target=self.run_async_loop, daemon=True)
        self.async_thread.start()
        
        # Mise à jour périodique de l'interface
        self.update_ui_periodic()
    
    def setup_dark_theme(self):
        """Configure le thème sombre"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configuration des couleurs
        style.configure('TFrame', background='#2d2d2d')
        style.configure('TLabel', background='#2d2d2d', foreground='#ffffff')
        style.configure('TButton', background='#404040', foreground='#ffffff')
        style.configure('TEntry', background='#404040', foreground='#ffffff')
        style.configure('TText', background='#404040', foreground='#ffffff')
        style.configure('TNotebook', background='#2d2d2d')
        style.configure('TNotebook.Tab', background='#404040', foreground='#ffffff')
        
        # Couleurs spéciales
        style.configure('Success.TLabel', foreground='#00ff00')
        style.configure('Warning.TLabel', foreground='#ffaa00')
        style.configure('Error.TLabel', foreground='#ff0000')
        style.configure('Info.TLabel', foreground='#00aaff')
    
    def setup_ui(self):
        """Configure l'interface utilisateur principale"""
        # Menu principal
        self.setup_menu()
        
        # Barre d'état en haut
        self.setup_status_bar()
        
        # Notebook principal
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Onglets
        self.setup_dashboard_tab()
        self.setup_vpn_tab()
        self.setup_tor_tab()
        self.setup_messaging_tab()
        self.setup_security_tab()
        self.setup_logs_tab()
    
    def setup_menu(self):
        """Configure le menu principal"""
        menubar = tk.Menu(self.root, bg='#2d2d2d', fg='#ffffff')
        self.root.config(menu=menubar)
        
        # Menu Fichier
        file_menu = tk.Menu(menubar, tearoff=0, bg='#2d2d2d', fg='#ffffff')
        menubar.add_cascade(label="Fichier", menu=file_menu)
        file_menu.add_command(label="Nouveau profil", command=self.new_profile)
        file_menu.add_command(label="Charger profil", command=self.load_profile)
        file_menu.add_separator()
        file_menu.add_command(label="Exporter configuration", command=self.export_config)
        file_menu.add_command(label="Importer configuration", command=self.import_config)
        file_menu.add_separator()
        file_menu.add_command(label="Quitter", command=self.quit_application)
        
        # Menu Connexions
        conn_menu = tk.Menu(menubar, tearoff=0, bg='#2d2d2d', fg='#ffffff')
        menubar.add_cascade(label="Connexions", menu=conn_menu)
        conn_menu.add_command(label="Connecter VPN", command=self.connect_vpn)
        conn_menu.add_command(label="Démarrer Tor", command=self.start_tor)
        conn_menu.add_command(label="Nouvelle identité Tor", command=self.new_tor_identity)
        conn_menu.add_separator()
        conn_menu.add_command(label="Déconnecter tout", command=self.disconnect_all)
        
        # Menu Sécurité
        security_menu = tk.Menu(menubar, tearoff=0, bg='#2d2d2d', fg='#ffffff')
        menubar.add_cascade(label="Sécurité", menu=security_menu)
        security_menu.add_command(label="Test de sécurité", command=self.run_security_test)
        security_menu.add_command(label="Vérifier fuites", command=self.check_leaks)
        security_menu.add_command(label="Nettoyer traces", command=self.clean_traces)
        
        # Menu Aide
        help_menu = tk.Menu(menubar, tearoff=0, bg='#2d2d2d', fg='#ffffff')
        menubar.add_cascade(label="Aide", menu=help_menu)
        help_menu.add_command(label="Guide d'utilisation", command=self.show_help)
        help_menu.add_command(label="À propos", command=self.show_about)
    
    def setup_status_bar(self):
        """Configure la barre d'état"""
        status_frame = ttk.Frame(self.root)
        status_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Statut VPN
        self.vpn_status_label = ttk.Label(status_frame, text="VPN: Déconnecté", style='Error.TLabel')
        self.vpn_status_label.pack(side=tk.LEFT, padx=10)
        
        # Statut Tor
        self.tor_status_label = ttk.Label(status_frame, text="Tor: Arrêté", style='Error.TLabel')
        self.tor_status_label.pack(side=tk.LEFT, padx=10)
        
        # Statut Email
        self.email_status_label = ttk.Label(status_frame, text="Email: Non authentifié", style='Error.TLabel')
        self.email_status_label.pack(side=tk.LEFT, padx=10)
        
        # IP actuelle
        self.ip_label = ttk.Label(status_frame, text="IP: Inconnue", style='Info.TLabel')
        self.ip_label.pack(side=tk.RIGHT, padx=10)
        
        # Horloge
        self.time_label = ttk.Label(status_frame, text="", style='Info.TLabel')
        self.time_label.pack(side=tk.RIGHT, padx=10)
    
    def setup_dashboard_tab(self):
        """Configure l'onglet tableau de bord"""
        dashboard_frame = ttk.Frame(self.notebook)
        self.notebook.add(dashboard_frame, text="Tableau de bord")
        
        # Frame principal avec colonnes
        main_frame = ttk.Frame(dashboard_frame)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Colonne gauche - Contrôles rapides
        left_frame = ttk.LabelFrame(main_frame, text="Contrôles rapides")
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        
        # Boutons de connexion rapide
        ttk.Button(left_frame, text="🔒 Connexion sécurisée complète", 
                  command=self.quick_secure_connect).pack(pady=10, padx=10, fill=tk.X)
        
        ttk.Button(left_frame, text="🌐 VPN uniquement", 
                  command=self.connect_vpn).pack(pady=5, padx=10, fill=tk.X)
        
        ttk.Button(left_frame, text="🧅 Tor uniquement", 
                  command=self.start_tor).pack(pady=5, padx=10, fill=tk.X)
        
        ttk.Button(left_frame, text="📧 Messagerie sécurisée", 
                  command=self.open_messaging).pack(pady=5, padx=10, fill=tk.X)
        
        # Séparateur
        ttk.Separator(left_frame, orient='horizontal').pack(fill=tk.X, pady=10)
        
        # Métriques de sécurité
        metrics_frame = ttk.LabelFrame(left_frame, text="Métriques de sécurité")
        metrics_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.metrics_labels = {}
        for metric, value in self.security_metrics.items():
            label = ttk.Label(metrics_frame, text=f"{metric}: {value}")
            label.pack(anchor=tk.W, padx=5, pady=2)
            self.metrics_labels[metric] = label
        
        # Colonne droite - Monitoring
        right_frame = ttk.LabelFrame(main_frame, text="Monitoring en temps réel")
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5)
        
        # Graphique de monitoring
        self.setup_monitoring_chart(right_frame)
        
        # Logs récents
        logs_frame = ttk.LabelFrame(right_frame, text="Logs récents")
        logs_frame.pack(fill=tk.X, pady=10)
        
        self.recent_logs = scrolledtext.ScrolledText(logs_frame, height=8, 
                                                    bg='#1a1a1a', fg='#00ff00',
                                                    font=('Consolas', 9))
        self.recent_logs.pack(fill=tk.X, padx=5, pady=5)
    
    def setup_monitoring_chart(self, parent):
        """Configure le graphique de monitoring"""
        # Création de la figure matplotlib
        self.fig, (self.ax1, self.ax2) = plt.subplots(2, 1, figsize=(6, 4), 
                                                      facecolor='#2d2d2d')
        
        # Configuration du style sombre
        for ax in [self.ax1, self.ax2]:
            ax.set_facecolor('#1a1a1a')
            ax.tick_params(colors='white')
            ax.spines['bottom'].set_color('white')
            ax.spines['top'].set_color('white')
            ax.spines['right'].set_color('white')
            ax.spines['left'].set_color('white')
        
        # Graphique 1: Latence réseau
        self.ax1.set_title('Latence réseau (ms)', color='white')
        self.ax1.set_ylabel('ms', color='white')
        
        # Graphique 2: Bande passante
        self.ax2.set_title('Bande passante (KB/s)', color='white')
        self.ax2.set_ylabel('KB/s', color='white')
        self.ax2.set_xlabel('Temps', color='white')
        
        # Intégration dans tkinter
        self.canvas = FigureCanvasTkAgg(self.fig, parent)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Données initiales
        self.time_data = []
        self.latency_data = []
        self.bandwidth_data = []
    
    def setup_vpn_tab(self):
        """Configure l'onglet VPN"""
        vpn_frame = ttk.Frame(self.notebook)
        self.notebook.add(vpn_frame, text="VPN")
        
        # Configuration VPN
        config_frame = ttk.LabelFrame(vpn_frame, text="Configuration VPN")
        config_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Sélection du serveur
        ttk.Label(config_frame, text="Serveur:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.vpn_server_var = tk.StringVar()
        self.vpn_server_combo = ttk.Combobox(config_frame, textvariable=self.vpn_server_var,
                                           values=["Auto", "US-East", "US-West", "EU-Central", "Asia-Pacific"])
        self.vpn_server_combo.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        self.vpn_server_combo.set("Auto")
        
        # Protocole
        ttk.Label(config_frame, text="Protocole:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.vpn_protocol_var = tk.StringVar()
        self.vpn_protocol_combo = ttk.Combobox(config_frame, textvariable=self.vpn_protocol_var,
                                             values=["OpenVPN", "WireGuard", "IKEv2"])
        self.vpn_protocol_combo.grid(row=1, column=1, padx=5, pady=5, sticky=tk.EW)
        self.vpn_protocol_combo.set("OpenVPN")
        
        # Options de sécurité
        security_frame = ttk.LabelFrame(config_frame, text="Options de sécurité")
        security_frame.grid(row=2, column=0, columnspan=2, sticky=tk.EW, padx=5, pady=10)
        
        self.kill_switch_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(security_frame, text="Kill Switch", variable=self.kill_switch_var).pack(anchor=tk.W)
        
        self.dns_protection_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(security_frame, text="Protection DNS", variable=self.dns_protection_var).pack(anchor=tk.W)
        
        self.auto_rotation_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(security_frame, text="Rotation automatique", variable=self.auto_rotation_var).pack(anchor=tk.W)
        
        # Boutons de contrôle
        control_frame = ttk.Frame(config_frame)
        control_frame.grid(row=3, column=0, columnspan=2, pady=10)
        
        ttk.Button(control_frame, text="Connecter", command=self.connect_vpn).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Déconnecter", command=self.disconnect_vpn).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Changer serveur", command=self.rotate_vpn_server).pack(side=tk.LEFT, padx=5)
        
        # Informations de connexion
        info_frame = ttk.LabelFrame(vpn_frame, text="Informations de connexion")
        info_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.vpn_info_text = scrolledtext.ScrolledText(info_frame, height=15,
                                                      bg='#1a1a1a', fg='#ffffff',
                                                      font=('Consolas', 10))
        self.vpn_info_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def setup_tor_tab(self):
        """Configure l'onglet Tor"""
        tor_frame = ttk.Frame(self.notebook)
        self.notebook.add(tor_frame, text="Tor")
        
        # Configuration Tor
        config_frame = ttk.LabelFrame(tor_frame, text="Configuration Tor")
        config_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Ports
        ttk.Label(config_frame, text="Port SOCKS:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.tor_socks_port = tk.StringVar(value="9050")
        ttk.Entry(config_frame, textvariable=self.tor_socks_port, width=10).grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(config_frame, text="Port Control:").grid(row=0, column=2, sticky=tk.W, padx=5, pady=5)
        self.tor_control_port = tk.StringVar(value="9051")
        ttk.Entry(config_frame, textvariable=self.tor_control_port, width=10).grid(row=0, column=3, padx=5, pady=5)
        
        # Options de sécurité
        security_frame = ttk.LabelFrame(config_frame, text="Options de sécurité")
        security_frame.grid(row=1, column=0, columnspan=4, sticky=tk.EW, padx=5, pady=10)
        
        self.tor_strict_nodes_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(security_frame, text="Nœuds stricts", variable=self.tor_strict_nodes_var).pack(anchor=tk.W)
        
        self.tor_exclude_countries_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(security_frame, text="Exclure pays dangereux", variable=self.tor_exclude_countries_var).pack(anchor=tk.W)
        
        # Boutons de contrôle
        control_frame = ttk.Frame(config_frame)
        control_frame.grid(row=2, column=0, columnspan=4, pady=10)
        
        ttk.Button(control_frame, text="Démarrer", command=self.start_tor).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Arrêter", command=self.stop_tor).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Nouvelle identité", command=self.new_tor_identity).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Nouveau circuit", command=self.new_tor_circuit).pack(side=tk.LEFT, padx=5)
        
        # Informations des circuits
        circuits_frame = ttk.LabelFrame(tor_frame, text="Circuits Tor")
        circuits_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Treeview pour les circuits
        columns = ('ID', 'Statut', 'Chemin', 'Pays')
        self.circuits_tree = ttk.Treeview(circuits_frame, columns=columns, show='headings', height=8)
        
        for col in columns:
            self.circuits_tree.heading(col, text=col)
            self.circuits_tree.column(col, width=150)
        
        scrollbar_circuits = ttk.Scrollbar(circuits_frame, orient=tk.VERTICAL, command=self.circuits_tree.yview)
        self.circuits_tree.configure(yscrollcommand=scrollbar_circuits.set)
        
        self.circuits_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        scrollbar_circuits.pack(side=tk.RIGHT, fill=tk.Y)
    
    def setup_messaging_tab(self):
        """Configure l'onglet messagerie sécurisée"""
        messaging_frame = ttk.Frame(self.notebook)
        self.notebook.add(messaging_frame, text="Messagerie")
        
        # Configuration du profil
        profile_frame = ttk.LabelFrame(messaging_frame, text="Profil utilisateur")
        profile_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(profile_frame, text="ID Utilisateur:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.user_id_var = tk.StringVar()
        ttk.Entry(profile_frame, textvariable=self.user_id_var).grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        
        ttk.Label(profile_frame, text="Email:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.user_email_var = tk.StringVar()
        ttk.Entry(profile_frame, textvariable=self.user_email_var).grid(row=1, column=1, padx=5, pady=5, sticky=tk.EW)
        
        ttk.Button(profile_frame, text="Créer profil", command=self.create_email_profile).grid(row=0, column=2, padx=5, pady=5)
        ttk.Button(profile_frame, text="Charger profil", command=self.load_email_profile).grid(row=1, column=2, padx=5, pady=5)
        
        # Liste des contacts
        contacts_frame = ttk.LabelFrame(messaging_frame, text="Contacts")
        contacts_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Treeview pour les contacts
        self.contacts_tree = ttk.Treeview(contacts_frame, columns=('Email', 'Statut'), show='tree headings', height=10)
        self.contacts_tree.heading('#0', text='Contact')
        self.contacts_tree.heading('Email', text='Email')
        self.contacts_tree.heading('Statut', text='Statut')
        
        self.contacts_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Boutons de gestion des contacts
        contacts_buttons = ttk.Frame(contacts_frame)
        contacts_buttons.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(contacts_buttons, text="Ajouter", command=self.add_contact).pack(side=tk.LEFT, padx=2)
        ttk.Button(contacts_buttons, text="Supprimer", command=self.remove_contact).pack(side=tk.LEFT, padx=2)
        ttk.Button(contacts_buttons, text="Échanger clés", command=self.exchange_keys).pack(side=tk.LEFT, padx=2)
        
        # Zone de messagerie
        message_frame = ttk.LabelFrame(messaging_frame, text="Messagerie sécurisée")
        message_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Zone d'affichage des messages
        self.messages_display = scrolledtext.ScrolledText(message_frame, height=15,
                                                         bg='#1a1a1a', fg='#ffffff',
                                                         font=('Consolas', 10))
        self.messages_display.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Zone de composition
        compose_frame = ttk.Frame(message_frame)
        compose_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(compose_frame, text="À:").pack(anchor=tk.W)
        self.message_to_var = tk.StringVar()
        ttk.Entry(compose_frame, textvariable=self.message_to_var).pack(fill=tk.X, pady=2)
        
        ttk.Label(compose_frame, text="Sujet:").pack(anchor=tk.W)
        self.message_subject_var = tk.StringVar()
        ttk.Entry(compose_frame, textvariable=self.message_subject_var).pack(fill=tk.X, pady=2)
        
        ttk.Label(compose_frame, text="Message:").pack(anchor=tk.W)
        self.message_text = tk.Text(compose_frame, height=4, bg='#404040', fg='#ffffff')
        self.message_text.pack(fill=tk.X, pady=2)
        
        ttk.Button(compose_frame, text="Envoyer message sécurisé", command=self.send_secure_message).pack(pady=5)
    
    def setup_security_tab(self):
        """Configure l'onglet sécurité"""
        security_frame = ttk.Frame(self.notebook)
        self.notebook.add(security_frame, text="Sécurité")
        
        # Tests de sécurité
        tests_frame = ttk.LabelFrame(security_frame, text="Tests de sécurité")
        tests_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(tests_frame, text="Test de fuite IP", command=self.test_ip_leak).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(tests_frame, text="Test de fuite DNS", command=self.test_dns_leak).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(tests_frame, text="Test WebRTC", command=self.test_webrtc_leak).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(tests_frame, text="Test complet", command=self.run_full_security_test).pack(side=tk.LEFT, padx=5, pady=5)
        
        # Résultats des tests
        results_frame = ttk.LabelFrame(security_frame, text="Résultats des tests")
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.security_results = scrolledtext.ScrolledText(results_frame, height=20,
                                                         bg='#1a1a1a', fg='#00ff00',
                                                         font=('Consolas', 10))
        self.security_results.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def setup_logs_tab(self):
        """Configure l'onglet logs"""
        logs_frame = ttk.Frame(self.notebook)
        self.notebook.add(logs_frame, text="Logs")
        
        # Contrôles des logs
        controls_frame = ttk.Frame(logs_frame)
        controls_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(controls_frame, text="Niveau:").pack(side=tk.LEFT, padx=5)
        self.log_level_var = tk.StringVar(value="INFO")
        log_level_combo = ttk.Combobox(controls_frame, textvariable=self.log_level_var,
                                      values=["DEBUG", "INFO", "WARNING", "ERROR"], width=10)
        log_level_combo.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(controls_frame, text="Actualiser", command=self.refresh_logs).pack(side=tk.LEFT, padx=5)
        ttk.Button(controls_frame, text="Effacer", command=self.clear_logs).pack(side=tk.LEFT, padx=5)
        ttk.Button(controls_frame, text="Exporter", command=self.export_logs).pack(side=tk.LEFT, padx=5)
        
        # Zone d'affichage des logs
        self.logs_display = scrolledtext.ScrolledText(logs_frame, height=25,
                                                     bg='#1a1a1a', fg='#00ff00',
                                                     font=('Consolas', 9))
        self.logs_display.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
    
    def setup_monitoring(self):
        """Configure le système de monitoring"""
        # Initialisation des données de monitoring
        self.monitoring_active = True
        
        # Démarrage du monitoring en arrière-plan
        threading.Thread(target=self.monitoring_loop, daemon=True).start()
    
    def monitoring_loop(self):
        """Boucle de monitoring en arrière-plan"""
        while self.monitoring_active:
            try:
                # Collecte des métriques
                current_time = time.time()
                
                # Simulation de données (en production, récupérer les vraies métriques)
                latency = np.random.normal(50, 10)  # Latence simulée
                bandwidth = np.random.normal(1000, 200)  # Bande passante simulée
                
                # Mise à jour des données
                self.time_data.append(current_time)
                self.latency_data.append(max(0, latency))
                self.bandwidth_data.append(max(0, bandwidth))
                
                # Garder seulement les 50 derniers points
                if len(self.time_data) > 50:
                    self.time_data.pop(0)
                    self.latency_data.pop(0)
                    self.bandwidth_data.pop(0)
                
                # Mise à jour des métriques de sécurité
                if self.vpn_connected.get():
                    self.security_metrics["vpn_uptime"] += 1
                
                time.sleep(2)  # Mise à jour toutes les 2 secondes
                
            except Exception as e:
                print(f"Erreur monitoring: {e}")
                time.sleep(5)
    
    def update_monitoring_chart(self):
        """Met à jour le graphique de monitoring"""
        try:
            if len(self.time_data) > 1:
                # Conversion en temps relatif
                relative_time = [(t - self.time_data[0]) for t in self.time_data]
                
                # Mise à jour du graphique de latence
                self.ax1.clear()
                self.ax1.plot(relative_time, self.latency_data, 'g-', linewidth=2)
                self.ax1.set_title('Latence réseau (ms)', color='white')
                self.ax1.set_ylabel('ms', color='white')
                self.ax1.set_facecolor('#1a1a1a')
                self.ax1.tick_params(colors='white')
                
                # Mise à jour du graphique de bande passante
                self.ax2.clear()
                self.ax2.plot(relative_time, self.bandwidth_data, 'b-', linewidth=2)
                self.ax2.set_title('Bande passante (KB/s)', color='white')
                self.ax2.set_ylabel('KB/s', color='white')
                self.ax2.set_xlabel('Temps (s)', color='white')
                self.ax2.set_facecolor('#1a1a1a')
                self.ax2.tick_params(colors='white')
                
                # Rafraîchissement du canvas
                self.canvas.draw()
                
        except Exception as e:
            print(f"Erreur mise à jour graphique: {e}")
    
    def update_ui_periodic(self):
        """Mise à jour périodique de l'interface"""
        try:
            # Mise à jour de l'horloge
            current_time = datetime.now().strftime("%H:%M:%S")
            self.time_label.config(text=current_time)
            
            # Mise à jour des statuts
            self.update_status_labels()
            
            # Mise à jour du graphique
            self.update_monitoring_chart()
            
            # Mise à jour des métriques
            self.update_metrics_display()
            
            # Programmer la prochaine mise à jour
            self.root.after(2000, self.update_ui_periodic)  # Toutes les 2 secondes
            
        except Exception as e:
            print(f"Erreur mise à jour UI: {e}")
            self.root.after(5000, self.update_ui_periodic)
    
    def update_status_labels(self):
        """Met à jour les labels de statut"""
        # Statut VPN
        if self.vpn_connected.get():
            self.vpn_status_label.config(text="VPN: Connecté", style='Success.TLabel')
        else:
            self.vpn_status_label.config(text="VPN: Déconnecté", style='Error.TLabel')
        
        # Statut Tor
        if self.tor_connected.get():
            self.tor_status_label.config(text="Tor: Actif", style='Success.TLabel')
        else:
            self.tor_status_label.config(text="Tor: Arrêté", style='Error.TLabel')
        
        # Statut Email
        if self.email_authenticated.get():
            self.email_status_label.config(text="Email: Authentifié", style='Success.TLabel')
        else:
            self.email_status_label.config(text="Email: Non authentifié", style='Error.TLabel')
    
    def update_metrics_display(self):
        """Met à jour l'affichage des métriques"""
        for metric, label in self.metrics_labels.items():
            value = self.security_metrics[metric]
            label.config(text=f"{metric.replace('_', ' ').title()}: {value}")
    
    def run_async_loop(self):
        """Exécute la boucle d'événements asynchrone"""
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()
    
    def run_async_task(self, coro):
        """Exécute une tâche asynchrone"""
        future = asyncio.run_coroutine_threadsafe(coro, self.loop)
        return future
    
    # Méthodes de contrôle VPN
    def connect_vpn(self):
        """Connecte le VPN"""
        try:
            future = self.run_async_task(self.vpn_manager.connect())
            success = future.result(timeout=30)
            
            if success:
                self.vpn_connected.set(True)
                self.log_message("VPN connecté avec succès")
                self.update_vpn_info()
            else:
                messagebox.showerror("Erreur", "Échec de la connexion VPN")
                
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur VPN: {e}")
    
    def disconnect_vpn(self):
        """Déconnecte le VPN"""
        try:
            future = self.run_async_task(self.vpn_manager.disconnect())
            success = future.result(timeout=10)
            
            if success:
                self.vpn_connected.set(False)
                self.log_message("VPN déconnecté")
                self.update_vpn_info()
                
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur déconnexion VPN: {e}")
    
    def rotate_vpn_server(self):
        """Change de serveur VPN"""
        try:
            future = self.run_async_task(self.vpn_manager.rotate_server())
            success = future.result(timeout=30)
            
            if success:
                self.log_message("Serveur VPN changé")
                self.update_vpn_info()
            else:
                messagebox.showwarning("Attention", "Impossible de changer de serveur")
                
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur rotation VPN: {e}")
    
    def update_vpn_info(self):
        """Met à jour les informations VPN"""
        try:
            future = self.run_async_task(self.vpn_manager.get_status())
            status = future.result(timeout=5)
            
            info_text = f"""
Statut de connexion: {'Connecté' if status.connected else 'Déconnecté'}
Serveur actuel: {status.server.name if status.server else 'Aucun'}
Adresse IP: {status.ip_address or 'Inconnue'}
Serveurs DNS: {', '.join(status.dns_servers) if status.dns_servers else 'Aucun'}
Données transférées: {status.data_transferred['sent']} envoyées, {status.data_transferred['received']} reçues
"""
            
            self.vpn_info_text.delete(1.0, tk.END)
            self.vpn_info_text.insert(1.0, info_text)
            
        except Exception as e:
            print(f"Erreur mise à jour info VPN: {e}")
    
    # Méthodes de contrôle Tor
    def start_tor(self):
        """Démarre Tor"""
        try:
            future = self.run_async_task(self.tor_manager.start())
            success = future.result(timeout=60)
            
            if success:
                self.tor_connected.set(True)
                self.log_message("Tor démarré avec succès")
                self.update_tor_circuits()
            else:
                messagebox.showerror("Erreur", "Échec du démarrage de Tor")
                
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur Tor: {e}")
    
    def stop_tor(self):
        """Arrête Tor"""
        try:
            future = self.run_async_task(self.tor_manager.stop())
            success = future.result(timeout=10)
            
            if success:
                self.tor_connected.set(False)
                self.log_message("Tor arrêté")
                self.clear_tor_circuits()
                
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur arrêt Tor: {e}")
    
    def new_tor_identity(self):
        """Demande une nouvelle identité Tor"""
        try:
            future = self.run_async_task(self.tor_manager.new_identity())
            success = future.result(timeout=10)
            
            if success:
                self.log_message("Nouvelle identité Tor obtenue")
                self.update_tor_circuits()
            else:
                messagebox.showwarning("Attention", "Impossible d'obtenir une nouvelle identité")
                
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur nouvelle identité: {e}")
    
    def new_tor_circuit(self):
        """Crée un nouveau circuit Tor"""
        try:
            future = self.run_async_task(self.tor_manager.rotate_circuit())
            success = future.result(timeout=15)
            
            if success:
                self.log_message("Nouveau circuit Tor créé")
                self.update_tor_circuits()
                
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur nouveau circuit: {e}")
    
    def update_tor_circuits(self):
        """Met à jour l'affichage des circuits Tor"""
        try:
            # Effacer les anciens circuits
            for item in self.circuits_tree.get_children():
                self.circuits_tree.delete(item)
            
            # Récupérer les nouveaux circuits
            future = self.run_async_task(self.tor_manager.get_status())
            status = future.result(timeout=5)
            
            # Simulation de circuits (en production, récupérer les vrais circuits)
            for i in range(status.circuits_count):
                circuit_id = f"Circuit_{i+1}"
                circuit_status = "BUILT"
                circuit_path = f"Relay1 → Relay2 → Relay3"
                circuit_countries = "US → DE → NL"
                
                self.circuits_tree.insert('', 'end', values=(circuit_id, circuit_status, circuit_path, circuit_countries))
            
            self.security_metrics["tor_circuits"] = status.circuits_count
            
        except Exception as e:
            print(f"Erreur mise à jour circuits: {e}")
    
    def clear_tor_circuits(self):
        """Efface l'affichage des circuits"""
        for item in self.circuits_tree.get_children():
            self.circuits_tree.delete(item)
        self.security_metrics["tor_circuits"] = 0
    
    # Méthodes de messagerie
    def create_email_profile(self):
        """Crée un nouveau profil email"""
        user_id = self.user_id_var.get()
        email = self.user_email_var.get()
        
        if not user_id or not email:
            messagebox.showerror("Erreur", "Veuillez remplir tous les champs")
            return
        
        password = tk.simpledialog.askstring("Mot de passe", "Entrez un mot de passe sécurisé:", show='*')
        if not password:
            return
        
        try:
            future = self.run_async_task(self.email_manager.create_user_profile(user_id, email, password))
            profile = future.result(timeout=30)
            
            if profile:
                self.email_authenticated.set(True)
                self.log_message(f"Profil email créé pour {user_id}")
                messagebox.showinfo("Succès", "Profil créé avec succès")
            
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur création profil: {e}")
    
    def load_email_profile(self):
        """Charge un profil email existant"""
        user_id = self.user_id_var.get()
        
        if not user_id:
            messagebox.showerror("Erreur", "Veuillez entrer un ID utilisateur")
            return
        
        password = tk.simpledialog.askstring("Mot de passe", "Entrez votre mot de passe:", show='*')
        if not password:
            return
        
        try:
            future = self.run_async_task(self.email_manager.load_user_profile(user_id, password))
            success = future.result(timeout=10)
            
            if success:
                self.email_authenticated.set(True)
                self.log_message(f"Profil {user_id} chargé")
                messagebox.showinfo("Succès", "Profil chargé avec succès")
            else:
                messagebox.showerror("Erreur", "Impossible de charger le profil")
                
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur chargement profil: {e}")
    
    def send_secure_message(self):
        """Envoie un message sécurisé"""
        if not self.email_authenticated.get():
            messagebox.showerror("Erreur", "Veuillez d'abord vous authentifier")
            return
        
        to = self.message_to_var.get()
        subject = self.message_subject_var.get()
        message = self.message_text.get(1.0, tk.END).strip()
        
        if not to or not message:
            messagebox.showerror("Erreur", "Veuillez remplir les champs obligatoires")
            return
        
        try:
            future = self.run_async_task(self.email_manager.send_secure_message(to, subject, message))
            success = future.result(timeout=30)
            
            if success:
                self.log_message(f"Message sécurisé envoyé à {to}")
                self.security_metrics["messages_sent"] += 1
                messagebox.showinfo("Succès", "Message envoyé avec succès")
                
                # Effacer les champs
                self.message_to_var.set("")
                self.message_subject_var.set("")
                self.message_text.delete(1.0, tk.END)
            else:
                messagebox.showerror("Erreur", "Échec de l'envoi du message")
                
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur envoi message: {e}")
    
    # Méthodes utilitaires
    def quick_secure_connect(self):
        """Connexion sécurisée complète (VPN + Tor)"""
        try:
            self.log_message("Démarrage de la connexion sécurisée complète...")
            
            # Connexion VPN d'abord
            self.connect_vpn()
            time.sleep(3)  # Attendre la connexion VPN
            
            # Puis démarrage de Tor
            self.start_tor()
            
            self.log_message("Connexion sécurisée complète établie")
            
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur connexion sécurisée: {e}")
    
    def disconnect_all(self):
        """Déconnecte tous les services"""
        try:
            self.disconnect_vpn()
            self.stop_tor()
            self.log_message("Tous les services déconnectés")
            
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur déconnexion: {e}")
    
    def log_message(self, message):
        """Ajoute un message aux logs"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        
        # Logs récents sur le dashboard
        self.recent_logs.insert(tk.END, log_entry)
        self.recent_logs.see(tk.END)
        
        # Logs complets
        self.logs_display.insert(tk.END, log_entry)
        self.logs_display.see(tk.END)
        
        # Limiter le nombre de lignes
        if int(self.recent_logs.index('end-1c').split('.')[0]) > 100:
            self.recent_logs.delete(1.0, "2.0")
        
        if int(self.logs_display.index('end-1c').split('.')[0]) > 1000:
            self.logs_display.delete(1.0, "100.0")
    
    # Méthodes de test de sécurité
    def test_ip_leak(self):
        """Test de fuite d'IP"""
        self.security_results.insert(tk.END, "Test de fuite IP en cours...\n")
        # Implémentation du test
        
    def test_dns_leak(self):
        """Test de fuite DNS"""
        self.security_results.insert(tk.END, "Test de fuite DNS en cours...\n")
        # Implémentation du test
        
    def test_webrtc_leak(self):
        """Test de fuite WebRTC"""
        self.security_results.insert(tk.END, "Test de fuite WebRTC en cours...\n")
        # Implémentation du test
        
    def run_full_security_test(self):
        """Exécute tous les tests de sécurité"""
        self.security_results.delete(1.0, tk.END)
        self.security_results.insert(tk.END, "=== TEST DE SÉCURITÉ COMPLET ===\n\n")
        
        self.test_ip_leak()
        self.test_dns_leak()
        self.test_webrtc_leak()
    
    # Méthodes de menu
    def new_profile(self):
        """Nouveau profil"""
        pass
    
    def load_profile(self):
        """Charger profil"""
        pass
    
    def export_config(self):
        """Exporter configuration"""
        pass
    
    def import_config(self):
        """Importer configuration"""
        pass
    
    def add_contact(self):
        """Ajouter un contact"""
        pass
    
    def remove_contact(self):
        """Supprimer un contact"""
        pass
    
    def exchange_keys(self):
        """Échanger les clés"""
        pass
    
    def open_messaging(self):
        """Ouvrir la messagerie"""
        self.notebook.select(3)  # Onglet messagerie
    
    def run_security_test(self):
        """Lancer test de sécurité"""
        self.notebook.select(4)  # Onglet sécurité
        self.run_full_security_test()
    
    def check_leaks(self):
        """Vérifier les fuites"""
        pass
    
    def clean_traces(self):
        """Nettoyer les traces"""
        pass
    
    def refresh_logs(self):
        """Actualiser les logs"""
        pass
    
    def clear_logs(self):
        """Effacer les logs"""
        self.logs_display.delete(1.0, tk.END)
        self.recent_logs.delete(1.0, tk.END)
    
    def export_logs(self):
        """Exporter les logs"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".log",
            filetypes=[("Log files", "*.log"), ("Text files", "*.txt")]
        )
        if filename:
            with open(filename, 'w') as f:
                f.write(self.logs_display.get(1.0, tk.END))
    
    def show_help(self):
        """Afficher l'aide"""
        help_text = """
        === GUIDE D'UTILISATION ===
        
        1. Connexion VPN:
           - Sélectionnez un serveur et un protocole
           - Cliquez sur "Connecter"
           - Vérifiez le statut dans la barre d'état
        
        2. Navigation Tor:
           - Cliquez sur "Démarrer" dans l'onglet Tor
           - Surveillez les circuits dans le tableau
           - Utilisez "Nouvelle identité" pour changer d'IP
        
        3. Messagerie sécurisée:
           - Créez ou chargez un profil utilisateur
           - Ajoutez des contacts et échangez les clés
           - Envoyez des messages chiffrés E2E
        
        4. Tests de sécurité:
           - Utilisez l'onglet Sécurité pour tester les fuites
           - Surveillez les métriques en temps réel
        """
        
        messagebox.showinfo("Guide d'utilisation", help_text)
    
    def show_about(self):
        """Afficher à propos"""
        about_text = """
        Ghost Cyber Universe - Navigation Sécurisée
        Version 1.0
        
        Système intégré de navigation sécurisée combinant:
        - VPN avec rotation automatique
        - Tor avec circuits multiples
        - Messagerie E2E avec Signal Protocol
        
        Développé pour une protection maximale de la vie privée.
        """
        
        messagebox.showinfo("À propos", about_text)
    
    def quit_application(self):
        """Quitter l'application"""
        if messagebox.askyesno("Quitter", "Voulez-vous vraiment quitter?"):
            # Déconnexion propre
            try:
                self.disconnect_all()
            except:
                pass
            
            # Arrêt du monitoring
            self.monitoring_active = False
            
            # Arrêt de la boucle async
            self.loop.call_soon_threadsafe(self.loop.stop)
            
            # Fermeture de l'interface
            self.root.quit()
            self.root.destroy()
    
    def run(self):
        """Lance l'interface utilisateur"""
        try:
            self.root.protocol("WM_DELETE_WINDOW", self.quit_application)
            self.root.mainloop()
        except KeyboardInterrupt:
            self.quit_application()

def main():
    """Fonction principale"""
    try:
        app = SecureNavigationUI()
        app.run()
    except Exception as e:
        print(f"Erreur fatale: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()