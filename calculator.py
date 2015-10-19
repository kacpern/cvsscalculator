# -*- coding: utf-8 -*-
from __future__ import division  # true division

from collections import namedtuple, OrderedDict
import enum

from PySide import QtCore, QtGui

from ui import *
from src import colors, Cvss, CvssVectorError
import resources


version_info = namedtuple(u'version_info', u'major, minor, micro, releaselevel, serial')
version = version_info(1, 0, 0, u'beta', 1)


def get_version():
    v = u'{0}.{1}'.format(version.major, version.minor)
    if version.micro:
        v = u'{0}.{1}'.format(v, version.micro)
    if version[3:] == (u'alpha', 0):
        v = u'{0} pre-alpha'.format(v)
    elif version.releaselevel != u'final':
        v = u'{0} {1} {2}'.format(v, version.releaselevel, version.serial)
    return v


def color_from_range(value, minimum, maximum):
    reds = 0, 255, 255
    greens = 176, 192, 0
    blues = 80, 0, 0

    percentage = (value - minimum) / (maximum - minimum)

    if percentage <= 0.5:
        red = 2.0 * (percentage * reds[1] + (0.5 - percentage) * reds[0])
        green = 2.0 * (percentage * greens[1] + (0.5 - percentage) * greens[0])
        blue = 2.0 * (percentage * blues[1] + (0.5 - percentage) * blues[0])
    else:
        red = 2.0 * ((percentage - 0.5) * reds[2] + (1.0 - percentage) * reds[1])
        green = 2.0 * ((percentage - 0.5) * greens[2] + (1.0 - percentage) * greens[1])
        blue = 2.0 * ((percentage - 0.5) * blues[2] + (1.0 - percentage) * blues[1])

    return QtGui.QColor.fromRgb(red, green, blue)


def rgb_from_color(color):
    return u'rgb({0[0]}, {0[1]}, {0[2]})'.format(color.toTuple())


def rgba_from_color(color):
    return u'rgba({0[0]}, {0[1]}, {0[2]}, {0[3]})'.format(color.toTuple())


class Calculator(QtGui.QMainWindow, Ui_Calculator):

    def __init__(self):
        super(Calculator, self).__init__()

        self.cvss = Cvss()

        self.setup_ui()
        self.init_ui()

    def init_ui(self):
        app_icon = QtGui.QIcon(u':/icons/application-icon.png')
        clear_icon = QtGui.QIcon(u':/icons/form-clear.png')
        wizard_icon = QtGui.QIcon(u':/icons/wizard.png')
        quit_icon = QtGui.QIcon(u':/icons/application-exit.png')
        about_icon = QtGui.QIcon(u':/icons/help-about.png')

        self.setWindowIcon(app_icon)
        self.setWindowTitle(QtCore.QCoreApplication.applicationName())
        self.layout().setSizeConstraint(QtGui.QLayout.SetFixedSize)

        self.file_menu.setTitle(self.tr('&file_menu'))
        self.wizard_action.setText(u'{0}...'.format(self.tr('&wizard_action')))
        self.wizard_action.setIcon(wizard_icon)
        self.quit_action.setText(self.tr('&quit_action'))
        self.quit_action.setShortcut(u'Ctrl+Q')
        self.quit_action.setIcon(quit_icon)

        self.help_menu.setTitle(self.tr('&help_menu'))
        self.about_action.setText(self.tr('&about_action'))
        self.about_action.setIcon(about_icon)

        self.base_score_label.setStyleSheet(u'font-weight: bold;')
        self.base_score_label.setText(self.tr('base_score'))
        self.base_score.setRange(0, 100)
        self.base_score.setFormat(u'%v')
        self.base_score.setAlignment(QtCore.Qt.AlignCenter)

        self.impact_subscore_label.setText(self.tr('impact_subscore'))
        self.impact_subscore.setRange(0, 100)
        self.impact_subscore.setFormat(u'%v')
        self.impact_subscore.setAlignment(QtCore.Qt.AlignCenter)

        self.exploitability_subscore_label.setText(self.tr('exploitability_subscore'))
        self.exploitability_subscore.setRange(0, 100)
        self.exploitability_subscore.setFormat(u'%v')
        self.exploitability_subscore.setAlignment(QtCore.Qt.AlignCenter)

        self.temporal_score_label.setStyleSheet(u'font-weight: bold;')
        self.temporal_score_label.setText(self.tr('temporal_score'))
        self.temporal_score.setRange(0, 100)
        self.temporal_score.setFormat(u'%v')
        self.temporal_score.setAlignment(QtCore.Qt.AlignCenter)

        self.environmental_score_label.setStyleSheet(u'font-weight: bold;')
        self.environmental_score_label.setText(self.tr('environmental_score'))
        self.environmental_score.setRange(0, 100)
        self.environmental_score.setFormat(u'%v')
        self.environmental_score.setAlignment(QtCore.Qt.AlignCenter)

        self.modified_impact_subscore_label.setText(self.tr('modified_impact_subscore'))
        self.modified_impact_subscore.setRange(0, 100)
        self.modified_impact_subscore.setFormat(u'%v')
        self.modified_impact_subscore.setAlignment(QtCore.Qt.AlignCenter)

        self.score_label.setStyleSheet(u'font-weight: bold;')
        self.score_label.setText(self.tr('score'))
        self.score_lcd.setDigitCount(3)
        self.score_lcd.setSmallDecimalPoint(True)
        self.score_lcd.setFrameStyle(QtGui.QFrame.StyledPanel)
        self.score.setOrientation(QtCore.Qt.Vertical)
        self.score.setRange(0, 100)
        self.score.setTextVisible(False)

        self.vector_label.setStyleSheet(u'font-weight: bold;')
        self.vector_label.setText(self.tr('vector'))

        # cvss base score metrics
        self.base_metrics.setStyleSheet(u'QGroupBox { font-weight: bold; };')
        self.base_metrics.setTitle(self.tr('base_metrics'))

        self.exploitability_metrics.setStyleSheet(u'QGroupBox { font-weight: bold; };')
        self.exploitability_metrics.setTitle(self.tr('exploitability_metrics'))

        av_tooltips = (self.tr('network_tooltip', 'access_vector'),
                       self.tr('local_tooltip', 'access_vector'),
                       self.tr('adjacent_network_tooltip', 'access_vector'))
        self.access_vector_label.setText(self.tr('access_vector'))
        self.access_vector_label.setToolTip(self.tr('access_vector_tooltip'))
        self.access_vector.lineEdit().setReadOnly(True)
        self.access_vector.setWrapping(True)
        self.access_vector.setMaximum(len(Cvss.ACCESS_VECTOR) - 1)
        self.access_vector.textFromValue = lambda v: Cvss.ACCESS_VECTOR[v]
        self.access_vector.toolTipFromValue = lambda v: av_tooltips[v]

        ac_tooltips = (self.tr('low_tooltip', 'access_complexity'),
                       self.tr('medium_tooltip', 'access_complexity'),
                       self.tr('high_tooltip', 'access_complexity'))
        self.access_complexity_label.setText(self.tr('access_complexity'))
        self.access_complexity_label.setToolTip(self.tr('access_complexity_tooltip'))
        self.access_complexity.lineEdit().setReadOnly(True)
        self.access_complexity.setWrapping(True)
        self.access_complexity.setMaximum(len(Cvss.ACCESS_COMPLEXITY) - 1)
        self.access_complexity.textFromValue = lambda v: Cvss.ACCESS_COMPLEXITY[v]
        self.access_complexity.toolTipFromValue = lambda v: ac_tooltips[v]

        au_tooltips = (self.tr('none_tooltip', 'authentication'),
                       self.tr('single_instance_tooltip', 'authentication'),
                       self.tr('multiple_instances_tooltip', 'authentication'))
        self.authentication_label.setText(self.tr('authentication'))
        self.authentication_label.setToolTip(self.tr('authentication_tooltip'))
        self.authentication.lineEdit().setReadOnly(True)
        self.authentication.setWrapping(True)
        self.authentication.setMaximum(len(Cvss.AUTHENTICATION) - 1)
        self.authentication.textFromValue = lambda v: Cvss.AUTHENTICATION[v]
        self.authentication.toolTipFromValue = lambda v: au_tooltips[v]

        self.impact_metrics.setStyleSheet(u'QGroupBox { font-weight: bold; };')
        self.impact_metrics.setTitle(self.tr('impact_metrics'))

        c_tooltips = (self.tr('none_tooltip', 'confidentiality_impact'),
                      self.tr('partial_tooltip', 'confidentiality_impact'),
                      self.tr('complete_tooltip', 'confidentiality_impact'))
        self.confidentiality_impact_label.setText(self.tr('confidentiality_impact'))
        self.confidentiality_impact_label.setToolTip(self.tr('confidentiality_impact_tooltip'))
        self.confidentiality_impact.lineEdit().setReadOnly(True)
        self.confidentiality_impact.setWrapping(True)
        self.confidentiality_impact.setMaximum(len(Cvss.CONFIDENTIALITY) - 1)
        self.confidentiality_impact.textFromValue = lambda v: Cvss.CONFIDENTIALITY[v]
        self.confidentiality_impact.toolTipFromValue = lambda v: c_tooltips[v]

        i_tooltips = (self.tr('none_tooltip', 'integrity_impact'),
                      self.tr('partial_tooltip', 'integrity_impact'),
                      self.tr('complete_tooltip', 'integrity_impact'))
        self.integrity_impact_label.setText(self.tr('integrity_impact'))
        self.integrity_impact_label.setToolTip(self.tr('integrity_impact_tooltip'))
        self.integrity_impact.lineEdit().setReadOnly(True)
        self.integrity_impact.setWrapping(True)
        self.integrity_impact.setMaximum(len(Cvss.INTEGRITY) - 1)
        self.integrity_impact.textFromValue = lambda v: Cvss.INTEGRITY[v]
        self.integrity_impact.toolTipFromValue = lambda v: i_tooltips[v]

        a_tooltips = (self.tr('none_tooltip', 'availability_impact'),
                      self.tr('partial_tooltip', 'availability_impact'),
                      self.tr('complete_tooltip', 'availability_impact'))
        self.availability_impact_label.setText(self.tr('availability_impact'))
        self.availability_impact_label.setToolTip(self.tr('availability_impact_tooltip'))
        self.availability_impact.lineEdit().setReadOnly(True)
        self.availability_impact.setWrapping(True)
        self.availability_impact.setMaximum(len(Cvss.AVAILABILITY) - 1)
        self.availability_impact.textFromValue = lambda v: Cvss.AVAILABILITY[v]
        self.availability_impact.toolTipFromValue = lambda v: a_tooltips[v]

        # cvss temporal score metrics
        self.temporal_metrics.setStyleSheet(u'QGroupBox { font-weight: bold; };')
        self.temporal_metrics.setTitle(self.tr('temporal_metrics'))

        e_tooltips = (self.tr('not_defined_tooltip', 'exploitability'),
                      self.tr('unproven_tooltip', 'exploitability'),
                      self.tr('proof_of_concept_tooltip', 'exploitability'),
                      self.tr('functional_tooltip', 'exploitability'),
                      self.tr('high_tooltip', 'exploitability'))
        self.exploitability_label.setText(self.tr('exploitability'))
        self.exploitability_label.setToolTip(self.tr('exploitability_tooltip'))
        self.exploitability.lineEdit().setReadOnly(True)
        self.exploitability.setWrapping(True)
        self.exploitability.setMaximum(len(Cvss.EXPLOITABILITY) - 1)
        self.exploitability.textFromValue = lambda v: Cvss.EXPLOITABILITY[v]
        self.exploitability.toolTipFromValue = lambda v: e_tooltips[v]

        rl_tooltips = (self.tr('not_defined_tooltip', 'remediation_level'),
                       self.tr('unavailable_tooltip', 'remediation_level'),
                       self.tr('workaround_tooltip', 'remediation_level'),
                       self.tr('temporary_fix_tooltip', 'remediation_level'),
                       self.tr('official_fix_tooltip', 'remediation_level'))
        self.remediation_level_label.setText(self.tr('remediation_level'))
        self.remediation_level_label.setToolTip(self.tr('remediation_level_tooltip'))
        self.remediation_level.lineEdit().setReadOnly(True)
        self.remediation_level.setWrapping(True)
        self.remediation_level.setMaximum(len(Cvss.REMEDIATION_LEVEL) - 1)
        self.remediation_level.textFromValue = lambda v: Cvss.REMEDIATION_LEVEL[v]
        self.remediation_level.toolTipFromValue = lambda v: rl_tooltips[v]

        rc_tooltips = (self.tr('not_defined_tooltip', 'report_confidence'),
                       self.tr('unconfirmed_tooltip', 'report_confidence'),
                       self.tr('uncorroborated_tooltip', 'report_confidence'),
                       self.tr('confirmed_tooltip', 'report_confidence'))
        self.report_confidence_label.setText(self.tr('report_confidence'))
        self.report_confidence_label.setToolTip(self.tr('report_confidence_tooltip'))
        self.report_confidence.lineEdit().setReadOnly(True)
        self.report_confidence.setWrapping(True)
        self.report_confidence.setMaximum(len(Cvss.REPORT_CONFIDENCE) - 1)
        self.report_confidence.textFromValue = lambda v: Cvss.REPORT_CONFIDENCE[v]
        self.report_confidence.toolTipFromValue = lambda v: rc_tooltips[v]

        # cvss environmental score metrics
        self.environmental_metrics.setStyleSheet(u'QGroupBox { font-weight: bold; };')
        self.environmental_metrics.setTitle(self.tr('environmental_metrics'))

        self.general_modifiers.setStyleSheet(u'QGroupBox { font-weight: bold; };')
        self.general_modifiers.setTitle(self.tr('general_modifiers'))

        cdp_tooltips = (self.tr('not_defined_tooltip', 'collateral_damage_potential'),
                        self.tr('none_tooltip', 'collateral_damage_potential'),
                        self.tr('low_tooltip', 'collateral_damage_potential'),
                        self.tr('low_medium_tooltip', 'collateral_damage_potential'),
                        self.tr('medium_high_tooltip', 'collateral_damage_potential'),
                        self.tr('high_tooltip', 'collateral_damage_potential'))
        self.collateral_damage_potential_label.setText(self.tr('collateral_damage_potential'))
        self.collateral_damage_potential_label.setToolTip(self.tr('collateral_damage_potential_tooltip'))
        self.collateral_damage_potential.lineEdit().setReadOnly(True)
        self.collateral_damage_potential.setWrapping(True)
        self.collateral_damage_potential.setMaximum(len(Cvss.COLLATERAL_DAMAGE_POTENTIAL) - 1)
        self.collateral_damage_potential.textFromValue = lambda v: Cvss.COLLATERAL_DAMAGE_POTENTIAL[v]
        self.collateral_damage_potential.toolTipFromValue = lambda v: cdp_tooltips[v]

        td_tooltips = (self.tr('not_defined_tooltip', 'target_distribution'),
                       self.tr('none_tooltip', 'target_distribution'),
                       self.tr('low_tooltip', 'target_distribution'),
                       self.tr('medium_tooltip', 'target_distribution'),
                       self.tr('high_tooltip', 'target_distribution'))
        self.target_distribution_label.setText(self.tr('target_distribution'))
        self.target_distribution_label.setToolTip(self.tr('target_distribution_tooltip'))
        self.target_distribution.lineEdit().setReadOnly(True)
        self.target_distribution.setWrapping(True)
        self.target_distribution.setMaximum(len(Cvss.TARGET_DISTRIBUTION) - 1)
        self.target_distribution.textFromValue = lambda v: Cvss.TARGET_DISTRIBUTION[v]
        self.target_distribution.toolTipFromValue = lambda v: td_tooltips[v]

        self.impact_modifiers.setStyleSheet(u'QGroupBox { font-weight: bold; };')
        self.impact_modifiers.setTitle(self.tr('impact_modifiers'))

        cr_tooltips = (self.tr('not_defined_tooltip', 'confidentiality_requirement'),
                       self.tr('low_tooltip', 'confidentiality_requirement'),
                       self.tr('medium_tooltip', 'confidentiality_requirement'),
                       self.tr('high_tooltip', 'confidentiality_requirement'))
        self.confidentiality_requirement_label.setText(self.tr('confidentiality_requirement'))
        self.confidentiality_requirement_label.setToolTip(self.tr('confidentiality_requirement_tooltip'))
        self.confidentiality_requirement.lineEdit().setReadOnly(True)
        self.confidentiality_requirement.setWrapping(True)
        self.confidentiality_requirement.setMaximum(len(Cvss.CONFIDENTIALITY_REQUIREMENT) - 1)
        self.confidentiality_requirement.textFromValue = lambda v: Cvss.CONFIDENTIALITY_REQUIREMENT[v]
        self.confidentiality_requirement.toolTipFromValue = lambda v: cr_tooltips[v]

        ir_tooltips = (self.tr('not_defined_tooltip', 'integrity_requirement'),
                       self.tr('low_tooltip', 'integrity_requirement'),
                       self.tr('medium_tooltip', 'integrity_requirement'),
                       self.tr('high_tooltip', 'integrity_requirement'))
        self.integrity_requirement_label.setText(self.tr('integrity_requirement'))
        self.integrity_requirement_label.setToolTip(self.tr('integrity_requirement_tooltip'))
        self.integrity_requirement.lineEdit().setReadOnly(True)
        self.integrity_requirement.setWrapping(True)
        self.integrity_requirement.setMaximum(len(Cvss.INTEGRITY_REQUIREMENT) - 1)
        self.integrity_requirement.textFromValue = lambda v: Cvss.INTEGRITY_REQUIREMENT[v]
        self.integrity_requirement.toolTipFromValue = lambda v: ir_tooltips[v]

        ar_tooltips = (self.tr('not_defined_tooltip', 'availability_requirement'),
                       self.tr('low_tooltip', 'availability_requirement'),
                       self.tr('medium_tooltip', 'availability_requirement'),
                       self.tr('high_tooltip', 'availability_requirement'))
        self.availability_requirement_label.setText(self.tr('availability_requirement'))
        self.availability_requirement_label.setToolTip(self.tr('availability_requirement_tooltip'))
        self.availability_requirement.lineEdit().setReadOnly(True)
        self.availability_requirement.setWrapping(True)
        self.availability_requirement.setMaximum(len(Cvss.AVAILABILITY_REQUIREMENT) - 1)
        self.availability_requirement.textFromValue = lambda v: Cvss.AVAILABILITY_REQUIREMENT[v]
        self.availability_requirement.toolTipFromValue = lambda v: ar_tooltips[v]

        self.clear_button.setText(self.tr('clear'))
        self.clear_button.setIcon(clear_icon)

        self.wizard = WebApplicationVulnerabilityWizard(self)
        self.about_dialog = AboutDialog(unicode(get_version()), self)

        # connect signals
        self.wizard_action.triggered.connect(self.wizard.open)
        self.quit_action.triggered.connect(QtGui.qApp.quit)
        self.about_action.triggered.connect(self.about_dialog.open)

        self.base_score.valueChanged.connect(self.on_progress_bar_value_changed)
        self.impact_subscore.valueChanged.connect(self.on_progress_bar_value_changed)
        self.exploitability_subscore.valueChanged.connect(self.on_progress_bar_value_changed)
        self.temporal_score.valueChanged.connect(self.on_progress_bar_value_changed)
        self.environmental_score.valueChanged.connect(self.on_progress_bar_value_changed)
        self.modified_impact_subscore.valueChanged.connect(self.on_progress_bar_value_changed)
        self.score.valueChanged.connect(self.on_progress_bar_value_changed)

        self.vector.textEdited.connect(self.on_vector_text_edited)

        def update_metric(name, value):
            setattr(self.cvss, name, value)
            self.update_scores()
            self.update_vector()

        slot = lambda v: update_metric(u'access_vector', v)
        self.access_vector.valueChanged[str].connect(slot)
        slot = lambda v: update_metric(u'access_complexity', v)
        self.access_complexity.valueChanged[str].connect(slot)
        slot = lambda v: update_metric(u'authentication', v)
        self.authentication.valueChanged[str].connect(slot)

        slot = lambda v: update_metric(u'confidentiality_impact', v)
        self.confidentiality_impact.valueChanged[str].connect(slot)
        slot = lambda v: update_metric(u'integrity_impact', v)
        self.integrity_impact.valueChanged[str].connect(slot)
        slot = lambda v: update_metric(u'availability_impact', v)
        self.availability_impact.valueChanged[str].connect(slot)

        slot = lambda v: update_metric(u'exploitability', v)
        self.exploitability.valueChanged[str].connect(slot)
        slot = lambda v: update_metric(u'remediation_level', v)
        self.remediation_level.valueChanged[str].connect(slot)
        slot = lambda v: update_metric(u'report_confidence', v)
        self.report_confidence.valueChanged[str].connect(slot)

        slot = lambda v: update_metric(u'collateral_damage_potential', v)
        self.collateral_damage_potential.valueChanged[str].connect(slot)
        slot = lambda v: update_metric(u'target_distribution', v)
        self.target_distribution.valueChanged[str].connect(slot)

        slot = lambda v: update_metric(u'confidentiality_requirement', v)
        self.confidentiality_requirement.valueChanged[str].connect(slot)
        slot = lambda v: update_metric(u'integrity_requirement', v)
        self.integrity_requirement.valueChanged[str].connect(slot)
        slot = lambda v: update_metric(u'availability_requirement', v)
        self.availability_requirement.valueChanged[str].connect(slot)

        self.clear_button.pressed.connect(self.on_clear_button_pressed)

        self.wizard.accepted.connect(self.on_wizard_accepted)
        self.wizard.rejected.connect(self.on_wizard_rejected)

        self.update_scores()
        self.update_vector()

    def update_scores(self):
        self.base_score.setValue(self.cvss.base_score * 10)
        self.base_score.setFormat(unicode(self.cvss.base_score))

        self.exploitability_subscore.setValue(self.cvss.exploitability_subscore * 10)
        self.exploitability_subscore.setFormat(unicode(self.cvss.exploitability_subscore))

        self.impact_subscore.setValue(self.cvss.impact_subscore * 10)
        self.impact_subscore.setFormat(unicode(self.cvss.impact_subscore))

        self.temporal_score.setValue(self.cvss.temporal_score * 10)
        self.temporal_score.setFormat(unicode(self.cvss.temporal_score))

        self.environmental_score.setValue(self.cvss.environmental_score * 10)
        self.environmental_score.setFormat(unicode(self.cvss.environmental_score))

        self.modified_impact_subscore.setValue(self.cvss.modified_impact_subscore * 10)
        self.modified_impact_subscore.setFormat(unicode(self.cvss.modified_impact_subscore))

        color = color_from_range(self.cvss.score, 0, 10)
        self.score_lcd.setStyleSheet(u'color: {0};'.format(rgba_from_color(color)))
        self.score_lcd.display(unicode(self.cvss.score))
        self.score.setFormat(unicode(self.cvss.score))
        self.score.setValue(self.cvss.score * 10)

    def update_vector(self):
        self.vector.setStyleSheet(u'color: {0};'.format(rgba_from_color(colors.Black)))
        position = self.vector.cursorPosition()
        self.vector.setText(unicode(self.cvss.vector))
        self.vector.setCursorPosition(position)

    def update_score_metrics(self):
        self.update_base_score_metrics()
        self.update_temporal_score_metrics()
        self.update_environmental_score_metrics()

    def update_base_score_metrics(self):
        self.access_vector.setValue(Cvss.ACCESS_VECTOR.index(self.cvss.access_vector))
        self.access_complexity.setValue(Cvss.ACCESS_COMPLEXITY.index(self.cvss.access_complexity))
        self.authentication.setValue(Cvss.AUTHENTICATION.index(self.cvss.authentication))

        self.confidentiality_impact.setValue(Cvss.CONFIDENTIALITY.index(self.cvss.confidentiality_impact))
        self.integrity_impact.setValue(Cvss.INTEGRITY.index(self.cvss.integrity_impact))
        self.availability_impact.setValue(Cvss.AVAILABILITY.index(self.cvss.availability_impact))

    def update_temporal_score_metrics(self):
        self.exploitability.setValue(Cvss.EXPLOITABILITY.index(self.cvss.exploitability))
        self.remediation_level.setValue(Cvss.REMEDIATION_LEVEL.index(self.cvss.remediation_level))
        self.report_confidence.setValue(Cvss.REPORT_CONFIDENCE.index(self.cvss.report_confidence))

    def update_environmental_score_metrics(self):
        self.collateral_damage_potential.setValue(
            Cvss.COLLATERAL_DAMAGE_POTENTIAL.index(self.cvss.collateral_damage_potential))
        self.target_distribution.setValue(Cvss.TARGET_DISTRIBUTION.index(self.cvss.target_distribution))

        self.confidentiality_requirement.setValue(
            Cvss.CONFIDENTIALITY_REQUIREMENT.index(self.cvss.confidentiality_requirement))
        self.integrity_requirement.setValue(Cvss.INTEGRITY_REQUIREMENT.index(self.cvss.integrity_requirement))
        self.availability_requirement.setValue(Cvss.AVAILABILITY_REQUIREMENT.index(self.cvss.availability_requirement))

    def on_progress_bar_value_changed(self, value):
        progress_bar = self.sender()

        minimum = progress_bar.minimum()
        maximum = progress_bar.maximum()

        style_sheet = u'QProgressBar::chunk {{ margin: 1px; background-color: {0}; }};'
        color = color_from_range(value, minimum, maximum)
        color.setAlphaF(0.75)
        progress_bar.setStyleSheet(style_sheet.format(rgba_from_color(color)))

    def on_vector_text_edited(self, text):
        try:
            cvss = Cvss.from_vector(text)
        except CvssVectorError:
            self.vector.setStyleSheet(u'color: {0};'.format(rgba_from_color(colors.Red)))
        else:
            if not self.cvss == cvss:
                self.cvss = cvss
                self.update_score_metrics()
            # vector may still require updating
            self.update_vector()

    def on_clear_button_pressed(self):
        self.cvss.reset()
        self.update_score_metrics()

    def on_wizard_accepted(self):
        self.cvss = self.wizard.cvss.copy()
        self.update_score_metrics()  # wizard uses only base score metrics, but other metrics may have been set
        self.wizard.restart()

    def on_wizard_rejected(self):
        self.wizard.restart()


class AboutDialog(QtGui.QDialog, Ui_AboutDialog):

    def __init__(self, version, parent=None, flags=0):
        super(AboutDialog, self).__init__(parent=parent, f=flags)

        # logo_pixmap = QtGui.QPixmap(u':/images/logo-block.png')
        app_icon_pixmap = self.windowIcon().pixmap(36, 36)

        self.setup_ui()

        self.setWindowTitle(self.tr('window_title'))
        self.layout().setSizeConstraint(QtGui.QLayout.SetFixedSize)

        # self.app_icon.setStyleSheet(u'margin-top: 13px;')
        self.app_icon.setPixmap(app_icon_pixmap)

        self.heading.setStyleSheet(u'color: {0};'.format(rgba_from_color(colors.DarkGrey)))  # margin-top: 13px;
        self.heading.setTextFormat(QtCore.Qt.RichText)
        self.heading.setText(u'<h1>{0}</h1>'.format(QtCore.QCoreApplication.applicationName()))

        # self.logo.setPixmap(logo_pixmap)

        self.version.setStyleSheet(u'color: {0};'.format(rgba_from_color(colors.Grey)))
        self.version.setTextFormat(QtCore.Qt.RichText)
        self.version.setText(u'<tt>{0}</tt>'.format(version))

        self.description.setText(self.tr('description'))
        self.description.setWordWrap(True)
        self.description.setAlignment(QtCore.Qt.AlignJustify)

        self.footer.setStyleSheet(u'font-weight: bold; color: {0};'.format(rgba_from_color(colors.DarkGrey)))
        self.footer.setText(self.tr('footer'))
        self.footer.setTextFormat(QtCore.Qt.RichText)
        self.footer.setOpenExternalLinks(True)
        self.footer.setAlignment(QtCore.Qt.AlignJustify | QtCore.Qt.AlignBottom)


class IntroductionWizardPage(QtGui.QWizardPage, Ui_LogoWizardPage):

    def __init__(self, parent=None):
        super(IntroductionWizardPage, self).__init__(parent=parent)

        logo_pixmap = QtGui.QPixmap(u':/images/cvss-web.png')
        if not logo_pixmap.isNull():
            logo_pixmap = logo_pixmap.scaled(190, 190, QtCore.Qt.KeepAspectRatio, QtCore.Qt.SmoothTransformation)

        self.setup_ui(logo_pixmap)

        self.setTitle(self.tr('title'))
        self.setSubTitle(self.tr('subtitle'))


class CweWizardPage(QtGui.QWizardPage, Ui_ComboBoxWizardPage):

    def __init__(self, parent=None):
        super(CweWizardPage, self).__init__(parent=parent)

        self.setup_ui()

        self.setTitle(self.tr('title'))
        self.setSubTitle(self.tr('subtitle'))
        self.registerField(u'cwe', self.options)

    def initializePage(self):
        self.options.setCurrentIndex(0)


class ImpactAWizardPage(QtGui.QWizardPage, Ui_CheckBoxWizardPage):

    def __init__(self, parent=None):
        super(ImpactAWizardPage, self).__init__(parent=parent)

        button_count = 4
        self.setup_ui(button_count)

        fields = u'impact_a.read', u'impact_a.write', u'impact_a.delete', u'impact_a.execute'
        texts = self.tr('read'), self.tr('write'), self.tr('delete'), self.tr('execute')

        self.setTitle(self.tr('title'))
        self.setSubTitle(self.tr('subtitle'))
        for i in xrange(button_count):
            self.registerField(fields[i], self.options.button(i))
            self.labels[i].setWordWrap(True)
            self.labels[i].setText(texts[i])

        # handle events
        for i in xrange(button_count):
            button = self.options.button(i)

            def mouse_press_event(event, button=button):  # closure scope magic
                if event.button() == QtCore.Qt.MouseButton.LeftButton:
                    button.toggle()
                    return True
                else:
                    return super(ImpactAWizardPage, self).mousePressEvent(event)

            self.labels[i].mousePressEvent = mouse_press_event

        # connect signals
        self.isComplete = lambda: any(button.isChecked() for button in self.options.buttons())
        slot = lambda s: self.completeChanged.emit()
        for button in self.options.buttons():
            button.stateChanged.connect(slot)


class ImpactBWizardPage(QtGui.QWizardPage, Ui_CheckBoxWizardPage):

    def __init__(self, parent=None):
        super(ImpactBWizardPage, self).__init__(parent=parent)

        button_count = 5
        self.setup_ui(button_count)

        fields = u'impact_b.read', u'impact_b.write', u'impact_b.delete', u'impact_b.full', u'impact_b.execute'
        texts = self.tr('read'), self.tr('write'), self.tr('delete'), self.tr('full'), self.tr('execute')

        self.setTitle(self.tr('title'))
        self.setSubTitle(self.tr('subtitle'))
        for i in xrange(button_count):
            self.registerField(fields[i], self.options.button(i))
            self.labels[i].setWordWrap(True)
            self.labels[i].setText(texts[i])

        # handle events
        for i in xrange(button_count):
            button = self.options.button(i)

            def mouse_press_event(event, button=button):  # closure scope magic
                if event.button() == QtCore.Qt.MouseButton.LeftButton:
                    button.toggle()
                    return True
                else:
                    return super(ImpactBWizardPage, self).mousePressEvent(event)

            self.labels[i].mousePressEvent = mouse_press_event

        # connect signals
        self.isComplete = lambda: any(button.isChecked() for button in self.options.buttons())
        slot = lambda s: self.completeChanged.emit()
        for button in self.options.buttons():
            button.stateChanged.connect(slot)


class ImpactCWizardPage(QtGui.QWizardPage, Ui_CheckBoxWizardPage):

    def __init__(self, parent=None):
        super(ImpactCWizardPage, self).__init__(parent=parent)

        button_count = 5
        self.setup_ui(button_count)

        self.setTitle(self.tr('title'))
        self.setSubTitle(self.tr('subtitle'))
        fields = u'impact_c.read', u'impact_c.write', u'impact_c.block', u'impact_c.admin', u'impact_c.execute'
        texts = self.tr('read'), self.tr('write'), self.tr('block'), self.tr('admin'), self.tr('execute')

        for i in xrange(button_count):
            self.registerField(fields[i], self.options.button(i))
            self.labels[i].setWordWrap(True)
            self.labels[i].setText(texts[i])

        # handle events
        for i in xrange(button_count):
            button = self.options.button(i)

            def mouse_press_event(event, button=button):  # closure scope magic
                if event.button() == QtCore.Qt.MouseButton.LeftButton:
                    button.toggle()
                    return True
                else:
                    return super(ImpactCWizardPage, self).mousePressEvent(event)

            self.labels[i].mousePressEvent = mouse_press_event

        # connect signals
        self.isComplete = lambda: any(button.isChecked() for button in self.options.buttons())
        slot = lambda s: self.completeChanged.emit()
        for button in self.options.buttons():
            button.stateChanged.connect(slot)


class CrossSiteScritpingWizardPage(QtGui.QWizardPage, Ui_RadioWizardPage):

    def __init__(self, parent=None):
        super(CrossSiteScritpingWizardPage, self).__init__(parent=parent)

        button_count = 3
        self.setup_ui(button_count)

        self.setTitle(self.tr('title'))
        self.setSubTitle(self.tr('subtitle'))
        fields = u'xss.reflected', u'xss.stored', u'xss.dom_based'
        texts = self.tr('reflected'), self.tr('stored'), self.tr('dom_based')

        for i in xrange(button_count):
            self.registerField(fields[i], self.options.button(i))
            self.labels[i].setWordWrap(True)
            self.labels[i].setText(texts[i])

        # handle events
        for i in xrange(button_count):
            button = self.options.button(i)

            def mouse_press_event(event, button=button):  # closure scope magic
                if event.button() == QtCore.Qt.MouseButton.LeftButton:
                    button.setChecked(True)
                    return True
                else:
                    return super(CrossSiteScritpingWizardPage, self).mousePressEvent(event)

            self.labels[i].mousePressEvent = mouse_press_event


class PhpWizardPage(QtGui.QWizardPage, Ui_RadioWizardPage):

    def __init__(self, parent=None):
        super(PhpWizardPage, self).__init__(parent=parent)

        button_count = 2
        self.setup_ui(button_count)

        self.setTitle(self.tr('title'))
        self.setSubTitle(self.tr('subtitle'))
        fields = u'php.local', u'php.remote'
        texts = self.tr('local'), self.tr('remote')

        for i in xrange(button_count):
            self.registerField(fields[i], self.options.button(i))
            self.labels[i].setWordWrap(True)
            self.labels[i].setText(texts[i])

        # handle events
        for i in xrange(button_count):
            button = self.options.button(i)

            def mouse_press_event(event, button=button):  # closure scope magic
                if event.button() == QtCore.Qt.MouseButton.LeftButton:
                    button.setChecked(True)
                    return True
                else:
                    return super(PhpWizardPage, self).mousePressEvent(event)

            self.labels[i].mousePressEvent = mouse_press_event


class CrossSiteRequestForgeryWizardPage(QtGui.QWizardPage, Ui_RadioWizardPage):

    def __init__(self, parent=None):
        super(CrossSiteRequestForgeryWizardPage, self).__init__(parent=parent)

        button_count = 2
        self.setup_ui(button_count)

        self.setTitle(self.tr('title'))
        self.setSubTitle(self.tr('subtitle'))
        fields = u'csrf.no', u'csrf.yes'
        texts = self.tr('no'), self.tr('yes')

        for i in xrange(button_count):
            self.registerField(fields[i], self.options.button(i))
            self.labels[i].setWordWrap(True)
            self.labels[i].setText(texts[i])

        # handle events
        for i in xrange(button_count):
            button = self.options.button(i)

            def mouse_press_event(event, button=button):  # closure scope magic
                if event.button() == QtCore.Qt.MouseButton.LeftButton:
                    button.setChecked(True)
                    return True
                else:
                    return super(CrossSiteRequestForgeryWizardPage, self).mousePressEvent(event)

            self.labels[i].mousePressEvent = mouse_press_event


class AuthenticationWizardPage(QtGui.QWizardPage, Ui_RadioWizardPage):

    def __init__(self, parent=None):
        super(AuthenticationWizardPage, self).__init__(parent=parent)

        button_count = 4
        self.setup_ui(button_count)

        self.setTitle(self.tr('title'))
        self.setSubTitle(self.tr('subtitle'))
        fields = u'auth.none', u'auth.open', u'auth.closed', u'auth.special'
        texts = self.tr('none'), self.tr('open'), self.tr('closed'), self.tr('special')

        for i in xrange(button_count):
            self.registerField(fields[i], self.options.button(i))
            self.labels[i].setWordWrap(True)
            self.labels[i].setText(texts[i])

        # handle events
        for i in xrange(button_count):
            button = self.options.button(i)

            def mouse_press_event(event, button=button):  # closure scope magic
                if event.button() == QtCore.Qt.MouseButton.LeftButton:
                    button.setChecked(True)
                    return True
                else:
                    return super(AuthenticationWizardPage, self).mousePressEvent(event)

            self.labels[i].mousePressEvent = mouse_press_event


class ConfigurationWizardPage(QtGui.QWizardPage, Ui_RadioWizardPage):

    def __init__(self, parent=None):
        super(ConfigurationWizardPage, self).__init__(parent=parent)

        button_count = 4
        self.setup_ui(button_count)

        self.setTitle(self.tr('title'))
        self.setSubTitle(self.tr('subtitle'))
        fields = u'config.none', u'config.default', u'config.non_default', u'config.rare'
        texts = self.tr('none'), self.tr('default'), self.tr('non_default'), self.tr('rare')

        for i in xrange(button_count):
            self.registerField(fields[i], self.options.button(i))
            self.labels[i].setWordWrap(True)
            self.labels[i].setText(texts[i])

        # handle events
        for i in xrange(button_count):
            button = self.options.button(i)

            def mouse_press_event(event, button=button):  # closure scope magic
                if event.button() == QtCore.Qt.MouseButton.LeftButton:
                    button.setChecked(True)
                    return True
                else:
                    return super(ConfigurationWizardPage, self).mousePressEvent(event)

            self.labels[i].mousePressEvent = mouse_press_event


class DoneWizardPage(QtGui.QWizardPage, Ui_LogoWizardPage):

    def __init__(self, parent=None):
        super(DoneWizardPage, self).__init__(parent=parent)

        logo_pixmap = QtGui.QPixmap(u':/images/cvss-web.png')
        if not logo_pixmap.isNull():
            logo_pixmap = logo_pixmap.scaled(190, 190, QtCore.Qt.KeepAspectRatio, QtCore.Qt.SmoothTransformation)

        self.setup_ui(logo_pixmap)

        self.setTitle(self.tr('title'))
        self.setSubTitle(self.tr('subtitle'))


class WebApplicationVulnerabilityWizard(QtGui.QWizard):
    @enum.unique
    class Page(enum.IntEnum):
        Introduction = 0
        Cwe = 1
        ImpactA = 2
        ImpactB = 3
        ImpactC = 4
        CrossSiteScripting = 5
        Php = 6
        CrossSiteRequestForgery = 7
        Authentication = 8
        Configuration = 9
        Done = 10

    CWE = OrderedDict([(22, u'CWE-22: Path Traversal'),
                       (78, u'CWE-78: OS Command Injection'),
                       (79, u'CWE-79: Cross-Site Scripting'),
                       (89, u'CWE-89: SQL Injection'),
                       (90, u'CWE-90: LDAP Injection'),
                       (91, u'CWE-91: XML/XPath/XXE Injection'),
                       (94, u'CWE-94: Code Injection'),
                       (98, u'CWE-98: PHP File Inclusion'),
                       (113, u'CWE-113: HTTP Response Splitting'),
                       (200, u'CWE-200: Information Disclosure'),
                       (284, u'CWE-284: Improper Access Control'),
                       (287, u'CWE-287: Improper Authentication'),
                       (352, u'CWE-352: Cross-Site Request Forgery'),
                       (434, u'CWE-434: Unrestricted Upload of File with Dangerous Type'),
                       (601, u'CWE-601: Open Redirect')])

    def __init__(self, parent=None, flags=0):
        super(WebApplicationVulnerabilityWizard, self).__init__(parent=parent, flags=flags)

        self.cvss = Cvss()

        self.setWindowTitle(self.tr('window_title'))

        self.setPage(self.Page.Introduction, IntroductionWizardPage(self))
        self.setPage(self.Page.Cwe, CweWizardPage(self))
        self.setPage(self.Page.ImpactA, ImpactAWizardPage(self))
        self.setPage(self.Page.ImpactB, ImpactBWizardPage(self))
        self.setPage(self.Page.ImpactC, ImpactCWizardPage(self))
        self.setPage(self.Page.CrossSiteScripting, CrossSiteScritpingWizardPage(self))
        self.setPage(self.Page.Php, PhpWizardPage(self))
        self.setPage(self.Page.CrossSiteRequestForgery, CrossSiteRequestForgeryWizardPage(self))
        self.setPage(self.Page.Authentication, AuthenticationWizardPage(self))
        self.setPage(self.Page.Configuration, ConfigurationWizardPage(self))
        self.setPage(self.Page.Done, DoneWizardPage(self))

        self.page(self.Page.Cwe).options.addItems(self.CWE.values())

        self.setFixedSize(QtCore.QSize(600, 600))  # TODO: make dynamic

    def restart(self):
        self.cvss.reset()
        super(WebApplicationVulnerabilityWizard, self).restart()

    def nextId(self):
        current_id = self.currentId()
        cwe_id = self.CWE.keys()[self.field(u'cwe')]

        if current_id == self.Page.Introduction:
            next_id = self.Page.Cwe

        elif current_id == self.Page.Cwe:
            if cwe_id == 22:
                next_id = self.Page.ImpactA
            elif cwe_id in [90, 91, 284, 287]:
                next_id = self.Page.ImpactB
            elif cwe_id == 352:
                next_id = self.Page.ImpactC
            elif cwe_id == 79:
                next_id = self.Page.CrossSiteScripting
            elif cwe_id == 98:
                next_id = self.Page.Php
            elif cwe_id in [78, 89, 94, 434]:
                next_id = self.Page.CrossSiteRequestForgery
            elif cwe_id == 200:
                next_id = self.Page.Authentication
            elif cwe_id in [113, 601]:
                next_id = self.Page.Configuration
            else:
                next_id = -1

        elif current_id == self.Page.ImpactA:  # cwe_id == 22
            next_id = self.Page.CrossSiteRequestForgery

        elif current_id == self.Page.ImpactB:  # cwe_id in [90, 91, 284, 287]
            if cwe_id in [90, 91]:
                next_id = self.Page.CrossSiteRequestForgery
            else:  # cwe_id in [284, 287]
                next_id = self.Page.Configuration

        elif current_id == self.Page.ImpactC:  # cwe_id == 352
            next_id = self.Page.Done

        elif current_id == self.Page.CrossSiteScripting:  # cwe_id == 79
            if self.field(u'xss.stored'):
                next_id = self.Page.Authentication
            else:  # self.field('xss.reflected') or self.field('xss.dom_based')
                next_id = self.Page.Configuration

        elif current_id == self.Page.Php:  # cwe_id == 98
            if self.field(u'php.local'):
                next_id = self.Page.Authentication
            else:  # self.field('php.remote')
                next_id = self.Page.CrossSiteRequestForgery

        elif current_id == self.Page.CrossSiteRequestForgery:
            if self.field(u'csrf.yes'):
                next_id = self.Page.Done
            else:  # self.field('csrf.no')
                next_id = self.Page.Authentication

        elif current_id == self.Page.Authentication:
            if self.hasVisitedPage(self.Page.Php) and self.field(u'php.local'):
                next_id = self.Page.Done
            else:  # self.field('php.remote')
                next_id = self.Page.Configuration

        elif current_id == self.Page.Configuration:
            next_id = self.Page.Done

        else:  # current_id == self.Page.Done
            next_id = -1  # finish

        return next_id

    def done(self, r):
        if self.hasVisitedPage(self.Page.Cwe):
            cwe_id = self.CWE.keys()[self.field(u'cwe')]
            if cwe_id in [78, 94, 98, 434]:
                self.cvss.confidentiality_impact = u'Complete'
                self.cvss.integrity_impact = u'Complete'
                self.cvss.availability_impact = u'Complete'
            elif cwe_id in [79, 113, 601]:
                self.cvss.confidentiality_impact = u'None'
                self.cvss.integrity_impact = u'Partial'
                self.cvss.availability_impact = u'None'
                if cwe_id == 601:
                    self.cvss.access_vector = u'Network'
                    self.cvss.access_complexity = u'Medium'
                    self.cvss.authentication = u'None'
            elif cwe_id == 89:
                self.cvss.confidentiality_impact = u'Partial'
                self.cvss.integrity_impact = u'Partial'
                self.cvss.availability_impact = u'Partial'
            elif cwe_id == 200:
                self.cvss.confidentiality_impact = u'Partial'
                self.cvss.integrity_impact = u'None'
                self.cvss.availability_impact = u'None'
            elif cwe_id == 352:
                self.cvss.access_complexity = u'High'

        if self.hasVisitedPage(self.Page.ImpactA):
            if self.field(u'impact_a.read'):
                self.cvss.confidentiality_impact = u'Partial'
            if self.field(u'impact_a.write'):
                self.cvss.integrity_impact = u'Partial'
            if self.field(u'impact_a.delete'):
                self.cvss.availability_impact = u'Partial'
            if self.field(u'impact_a.execute'):
                self.cvss.confidentiality_impact = u'Complete'
                self.cvss.integrity_impact = u'Complete'
                self.cvss.availability_impact = u'Complete'

        if self.hasVisitedPage(self.Page.ImpactB):
            if self.field(u'impact_b.read'):
                self.cvss.confidentiality_impact = u'Partial'
            if self.field(u'impact_b.write'):
                self.cvss.integrity_impact = u'Partial'
            if self.field(u'impact_b.delete'):
                self.cvss.availability_impact = u'Partial'
            if self.field(u'impact_b.full'):
                self.cvss.confidentiality_impact = u'Partial'
                self.cvss.integrity_impact = u'Partial'
                self.cvss.availability_impact = u'Partial'
            if self.field(u'impact_b.execute'):
                self.cvss.confidentiality_impact = u'Complete'
                self.cvss.integrity_impact = u'Complete'
                self.cvss.availability_impact = u'Complete'

        if self.hasVisitedPage(self.Page.ImpactC):
            if self.field(u'impact_c.read'):
                self.cvss.confidentiality_impact = u'Partial'
            if self.field(u'impact_c.write'):
                self.cvss.integrity_impact = u'Partial'
            if self.field(u'impact_c.block'):
                self.cvss.availability_impact = u'Partial'
            if self.field(u'impact_c.admin'):
                self.cvss.confidentiality_impact = u'Partial'
                self.cvss.integrity_impact = u'Partial'
                self.cvss.availability_impact = u'Partial'
            if self.field(u'impact_c.execute'):
                self.cvss.confidentiality_impact = u'Complete'
                self.cvss.integrity_impact = u'Complete'
                self.cvss.availability_impact = u'Complete'

        if self.hasVisitedPage(self.Page.CrossSiteScripting):
            if self.field(u'xss.reflected') or self.field(u'xss.dom_based'):
                if self.cvss.access_complexity == u'Low':
                    self.cvss.access_complexity = u'Medium'
                elif self.cvss.access_complexity == u'Medium':
                    self.cvss.access_complexity = u'High'

        if self.hasVisitedPage(self.Page.Php):
            if self.field(u'php.local'):
                self.cvss.access_complexity = u'High'

        if self.hasVisitedPage(self.Page.CrossSiteRequestForgery):
            if self.field(u'csrf.yes'):
                self.cvss.access_complexity = u'High'

        if self.hasVisitedPage(self.Page.Authentication):
            if self.field(u'auth.closed') or self.field(u'auth.special'):
                self.cvss.authentication = u'Single Instance'

        if self.hasVisitedPage(self.Page.Configuration):
            if self.field(u'config.non_default'):
                if self.cvss.access_complexity == u'Low':
                    self.cvss.access_complexity = u'Medium'
                elif self.cvss.access_complexity == u'Medium':
                    self.cvss.access_complexity = u'High'
            elif self.field(u'config.rare'):
                self.cvss.access_complexity = u'High'

        super(WebApplicationVulnerabilityWizard, self).done(r)


def main(args):
    app = QtGui.QApplication(args)
    app.setApplicationName(u'CVSSv2 Calculator')
    app.setStyle(QtGui.QStyleFactory.create(u'Cleanlooks'))
    translator = QtCore.QTranslator()
    translator.load(u':/translations/en_GB.qm')
    app.installTranslator(translator)

    calculator = Calculator()
    calculator.show()

    sys.exit(app.exec_())

if __name__ == '__main__':
    import sys
    main(sys.argv)
