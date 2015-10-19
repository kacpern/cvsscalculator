# -*- coding: utf-8 -*-
from PySide import QtCore, QtGui


class ToolTipFromValueSpinBox(QtGui.QSpinBox):

    def event(self, event):
        if event.type() == QtGui.QHelpEvent.ToolTip:
            text = self.toolTipFromValue(self.value())
            QtGui.QToolTip.showText(event.globalPos(), text)
            return True
        else:
            return super(ToolTipFromValueSpinBox, self).event(event)

    def toolTipFromValue(self, val):
        return unicode(val)


class Ui_Calculator(object):

    def setup_ui(self):
        self.create_menu_bar()
        self.create_status_bar()

        central_widget = QtGui.QWidget(self)

        layout = QtGui.QVBoxLayout()
        layout.addWidget(self.create_score_widget(central_widget))
        layout.addWidget(self.create_base_metrics_widget(central_widget))
        layout.addWidget(self.create_temporal_metrics_widget(central_widget))
        layout.addWidget(self.create_environmental_metrics_widget(central_widget))

        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

    def create_menu_bar(self):
        menu_bar = self.menuBar()
        self.file_menu = menu_bar.addMenu('file_menu')
        self.help_menu = menu_bar.addMenu('help_menu')

        self.wizard_action = QtGui.QAction(self.file_menu)
        self.quit_action = QtGui.QAction(self.file_menu)
        self.about_action = QtGui.QAction(self.help_menu)

        self.file_menu.addAction(self.wizard_action)
        self.file_menu.addSeparator()
        self.file_menu.addAction(self.quit_action)
        self.help_menu.addAction(self.about_action)

    def create_status_bar(self):
        status_bar = self.statusBar()
        self.clear_button = QtGui.QPushButton(status_bar)
        filler = QtGui.QWidget(status_bar)

        status_bar.setSizeGripEnabled(False)
        status_bar.addPermanentWidget(self.clear_button)
        status_bar.addPermanentWidget(filler)

    def create_score_widget(self, parent):
        score_widget = QtGui.QWidget(parent)

        self.base_score_label = QtGui.QLabel(score_widget)
        self.base_score = QtGui.QProgressBar(score_widget)

        self.impact_subscore_label = QtGui.QLabel(score_widget)
        self.impact_subscore = QtGui.QProgressBar(score_widget)

        self.exploitability_subscore_label = QtGui.QLabel(score_widget)
        self.exploitability_subscore = QtGui.QProgressBar(score_widget)

        self.temporal_score_label = QtGui.QLabel(score_widget)
        self.temporal_score = QtGui.QProgressBar(score_widget)

        self.environmental_score_label = QtGui.QLabel(score_widget)
        self.environmental_score = QtGui.QProgressBar(score_widget)

        self.modified_impact_subscore_label = QtGui.QLabel(score_widget)
        self.modified_impact_subscore = QtGui.QProgressBar(score_widget)

        self.score_label = QtGui.QLabel(score_widget)
        self.score_lcd = QtGui.QLCDNumber(score_widget)
        self.score = QtGui.QProgressBar(score_widget)

        self.vector_label = QtGui.QLabel(score_widget)
        self.vector = QtGui.QLineEdit(score_widget)
        self.vector.setMinimumWidth(520)

        score_layout = QtGui.QHBoxLayout()
        score_layout.addWidget(self.score_lcd)
        score_layout.addWidget(self.score)

        layout = QtGui.QGridLayout()
        layout.addWidget(self.base_score_label, 0, 0)
        layout.addWidget(self.base_score, 0, 1)
        layout.addWidget(self.impact_subscore_label, 1, 0)
        layout.addWidget(self.impact_subscore, 1, 1)
        layout.addWidget(self.exploitability_subscore_label, 2, 0)
        layout.addWidget(self.exploitability_subscore, 2, 1)
        layout.addWidget(self.temporal_score_label, 3, 0)
        layout.addWidget(self.temporal_score, 3, 1)
        layout.addWidget(self.environmental_score_label, 4, 0)
        layout.addWidget(self.environmental_score, 4, 1)
        layout.addWidget(self.modified_impact_subscore_label, 5, 0)
        layout.addWidget(self.modified_impact_subscore, 5, 1)
        layout.addWidget(self.score_label, 0, 2, 1, 2)
        layout.addLayout(score_layout, 1, 2, 5, 2)
        layout.addWidget(self.vector_label, 6, 0, 1, 2)
        layout.addWidget(self.vector, 6, 1, 1, 3)
        for i in xrange(4):
            layout.setColumnStretch(i, 1)

        score_widget.setLayout(layout)
        return score_widget

    def create_base_metrics_widget(self, parent):
        self.base_metrics = QtGui.QGroupBox(parent)

        layout = QtGui.QHBoxLayout()
        layout.addWidget(self.create_exploitability_metrics_widget(self.base_metrics))
        layout.addWidget(self.create_impact_metrics_widget(self.base_metrics))

        self.base_metrics.setLayout(layout)
        return self.base_metrics

    def create_exploitability_metrics_widget(self, parent):
        self.exploitability_metrics = QtGui.QGroupBox(parent)

        self.access_vector_label = QtGui.QLabel(self.exploitability_metrics)
        self.access_vector = ToolTipFromValueSpinBox(self.exploitability_metrics)

        self.access_complexity_label = QtGui.QLabel(self.exploitability_metrics)
        self.access_complexity = ToolTipFromValueSpinBox(self.exploitability_metrics)

        self.authentication_label = QtGui.QLabel(self.exploitability_metrics)
        self.authentication = ToolTipFromValueSpinBox(self.exploitability_metrics)

        layout = QtGui.QGridLayout()
        layout.addWidget(self.access_vector_label, 0, 0)
        layout.addWidget(self.access_vector, 0, 1)
        layout.addWidget(self.access_complexity_label, 1, 0)
        layout.addWidget(self.access_complexity, 1, 1)
        layout.addWidget(self.authentication_label, 2, 0)
        layout.addWidget(self.authentication, 2, 1)

        self.exploitability_metrics.setLayout(layout)
        return self.exploitability_metrics

    def create_impact_metrics_widget(self, parent):
        self.impact_metrics = QtGui.QGroupBox(parent)

        self.confidentiality_impact_label = QtGui.QLabel(self.impact_metrics)
        self.confidentiality_impact = ToolTipFromValueSpinBox(self.impact_metrics)

        self.integrity_impact_label = QtGui.QLabel(self.impact_metrics)
        self.integrity_impact = ToolTipFromValueSpinBox(self.impact_metrics)

        self.availability_impact_label = QtGui.QLabel(self.impact_metrics)
        self.availability_impact = ToolTipFromValueSpinBox(self.impact_metrics)

        layout = QtGui.QGridLayout()
        layout.addWidget(self.confidentiality_impact_label, 0, 0)
        layout.addWidget(self.confidentiality_impact, 0, 1)
        layout.addWidget(self.integrity_impact_label, 1, 0)
        layout.addWidget(self.integrity_impact, 1, 1)
        layout.addWidget(self.availability_impact_label, 2, 0)
        layout.addWidget(self.availability_impact, 2, 1)

        self.impact_metrics.setLayout(layout)
        return self.impact_metrics

    def create_temporal_metrics_widget(self, parent):
        self.temporal_metrics = QtGui.QGroupBox(parent)

        self.exploitability_label = QtGui.QLabel(self.temporal_metrics)
        self.exploitability = ToolTipFromValueSpinBox(self.temporal_metrics)

        self.remediation_level_label = QtGui.QLabel(self.temporal_metrics)
        self.remediation_level = ToolTipFromValueSpinBox(self.temporal_metrics)

        self.report_confidence_label = QtGui.QLabel(self.temporal_metrics)
        self.report_confidence = ToolTipFromValueSpinBox(self.temporal_metrics)

        layout = QtGui.QGridLayout()
        layout.addWidget(self.exploitability_label, 0, 0)
        layout.addWidget(self.exploitability, 0, 1)
        layout.addWidget(self.remediation_level_label, 1, 0)
        layout.addWidget(self.remediation_level, 1, 1)
        layout.addWidget(self.report_confidence_label, 2, 0)
        layout.addWidget(self.report_confidence, 2, 1)

        self.temporal_metrics.setLayout(layout)
        return self.temporal_metrics

    def create_environmental_metrics_widget(self, parent):
        self.environmental_metrics = QtGui.QGroupBox(parent)

        layout = QtGui.QHBoxLayout()
        layout.addWidget(self.create_general_modifiers_widget(self.environmental_metrics))
        layout.addWidget(self.create_impact_modifiers_widget(self.environmental_metrics))

        self.environmental_metrics.setLayout(layout)
        return self.environmental_metrics

    def create_general_modifiers_widget(self, parent):
        self.general_modifiers = QtGui.QGroupBox(parent)

        self.collateral_damage_potential_label = QtGui.QLabel(self.general_modifiers)
        self.collateral_damage_potential = ToolTipFromValueSpinBox(self.general_modifiers)

        self.target_distribution_label = QtGui.QLabel(self.general_modifiers)
        self.target_distribution = ToolTipFromValueSpinBox(self.general_modifiers)

        layout = QtGui.QGridLayout()
        layout.addWidget(self.collateral_damage_potential_label, 0, 0)
        layout.addWidget(self.collateral_damage_potential, 0, 1)
        layout.addWidget(self.target_distribution_label, 1, 0)
        layout.addWidget(self.target_distribution, 1, 1)
        layout.setRowStretch(2, 1)

        self.general_modifiers.setLayout(layout)
        return self.general_modifiers

    def create_impact_modifiers_widget(self, parent):
        self.impact_modifiers = QtGui.QGroupBox(parent)

        self.confidentiality_requirement_label = QtGui.QLabel(self.impact_modifiers)
        self.confidentiality_requirement = ToolTipFromValueSpinBox(self.impact_modifiers)

        self.integrity_requirement_label = QtGui.QLabel(self.impact_modifiers)
        self.integrity_requirement = ToolTipFromValueSpinBox(self.impact_modifiers)

        self.availability_requirement_label = QtGui.QLabel(self.impact_modifiers)
        self.availability_requirement = ToolTipFromValueSpinBox(self.impact_modifiers)

        layout = QtGui.QGridLayout()
        layout.addWidget(self.confidentiality_requirement_label, 0, 0)
        layout.addWidget(self.confidentiality_requirement, 0, 1)
        layout.addWidget(self.integrity_requirement_label, 1, 0)
        layout.addWidget(self.integrity_requirement, 1, 1)
        layout.addWidget(self.availability_requirement_label, 2, 0)
        layout.addWidget(self.availability_requirement, 2, 1)

        self.impact_modifiers.setLayout(layout)
        return self.impact_modifiers


class Ui_AboutDialog(object):

    def setup_ui(self):
        self.app_icon = QtGui.QLabel(self)
        self.heading = QtGui.QLabel(self)
        # self.logo = QtGui.QLabel(self)
        self.version = QtGui.QLabel(self)
        self.description = QtGui.QLabel(self)
        self.footer = QtGui.QLabel(self)

        layout = QtGui.QGridLayout()
        layout.addWidget(self.app_icon, 0, 0)
        layout.addWidget(self.heading, 0, 1)
        # layout.addWidget(self.logo, 0, 2, 3, 1, QtCore.Qt.AlignRight | QtCore.Qt.AlignTop)
        layout.addWidget(self.version, 1, 0, 1, 2)
        layout.addWidget(self.description, 2, 0, 1, 2)
        layout.addWidget(self.footer, 4, 0, 1, 2)  # layout.addWidget(self.footer, 4, 0, 1, 3)
        layout.setColumnStretch(1, 1)
        # layout.setContentsMargins(13, 0, 0, 13)
        # layout.setRowMinimumHeight(4, 48)

        self.setLayout(layout)


class Ui_LogoWizardPage(object):

    def setup_ui(self, logo_pixmap):
        logo = QtGui.QLabel(self)
        logo.setPixmap(logo_pixmap)

        layout = QtGui.QVBoxLayout()
        layout.addWidget(logo, 1, alignment=QtCore.Qt.AlignRight | QtCore.Qt.AlignBottom)

        self.setLayout(layout)


class Ui_ComboBoxWizardPage(object):

    def setup_ui(self):
        self.options = QtGui.QComboBox(self)

        layout = QtGui.QVBoxLayout()
        layout.addWidget(self.options)

        self.setLayout(layout)


class Ui_CheckBoxWizardPage(object):

    def setup_ui(self, count):
        self.options = QtGui.QButtonGroup(self)
        self.options.setExclusive(False)
        self.labels = []

        for i in xrange(count):
            self.options.addButton(QtGui.QCheckBox(self), i)
            self.labels.append(QtGui.QLabel(self))

        layout = QtGui.QGridLayout()
        for i in xrange(count):
            layout.addWidget(self.options.button(i), i, 0)
            layout.addWidget(self.labels[i], i, 1)
        layout.setColumnMinimumWidth(0, 21)  # TODO: make dynamic
        layout.setColumnStretch(1, 1)

        self.setLayout(layout)


class Ui_RadioWizardPage(object):

    def setup_ui(self, count):
        self.options = QtGui.QButtonGroup(self)
        self.labels = []

        for i in xrange(count):
            self.options.addButton(QtGui.QRadioButton(self), i)
            self.labels.append(QtGui.QLabel(self))

        self.options.button(0).setChecked(True)

        layout = QtGui.QGridLayout()
        for i in xrange(count):
            layout.addWidget(self.options.button(i), i, 0)
            layout.addWidget(self.labels[i], i, 1)
        layout.setColumnMinimumWidth(0, 21)  # TODO: make dynamic
        layout.setColumnStretch(1, 1)

        self.setLayout(layout)
