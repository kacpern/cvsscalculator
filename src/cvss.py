# -*- coding: utf-8 -*-
from __future__ import division  # true division

__all__ = ['CvssError', 'CvssMetricError', 'CvssVectorError', 'Cvss', 'CvssV2', 'CvssV2Base', 'CvssV2Temporal',
           'CvssV2Environmental']

from decimal import BasicContext, Decimal as D, setcontext
from functools import total_ordering
import re


# Precision is set to nine. Rounding is set to ROUND_HALF_UP. All flags are cleared. All traps are enabled.
setcontext(BasicContext)

ROUND_ONE_PLACE = D('10')**-1
ROUND_TWO_PLACES = D('10')**-2


class CvssError(Exception):
    pass


class CvssMetricError(CvssError):

    def __str__(self):
        return u'Invalid value {1!r} for CVSSv2 metric {0!r}'.format(*self.args)


class CvssVectorError(CvssError):

    def __str__(self):
        return u'Invalid value {0!r} for CVSSv2 vector'.format(self.args[0])


def _reversed(d):
    """
    Return a dictionary with keys and values swapped
    """
    return dict((v, k) for k, v in d.iteritems())

_RE_CAPITALS = re.compile(ur'([A-Z_][-a-z ]*)')


def _from_capitals(d, first=False):
    r = dict([(''.join([a[0] for a in _RE_CAPITALS.split(k) if a][:first and 1 or None]), k) for k in d.iterkeys()])
    r.update(_reversed(r))
    return r


@total_ordering
class CvssV2Base(object):
    RE_VECTOR = re.compile(ur'^AV:(?P<AV>[NAL])/'
                           ur'AC:(?P<AC>[LMH])/'
                           ur'Au:(?P<Au>[NSM])/'
                           ur'C:(?P<C>[CPN])/'
                           ur'I:(?P<I>[CPN])/'
                           ur'A:(?P<A>[CPN])$',
                           re.IGNORECASE)

    ACCESS_VECTOR = u'Network', u'Local', u'Adjacent Network'
    ACCESS_COMPLEXITY = u'Low', u'Medium', u'High'
    AUTHENTICATION = u'None', u'Single Instance', u'Multiple Instances'
    CONFIDENTIALITY = u'None', u'Partial', u'Complete'
    AVAILABILITY = INTEGRITY = CONFIDENTIALITY

    AV = dict(zip(ACCESS_VECTOR, (D('1'), D('.395'), D('.646'))))
    AC = dict(zip(ACCESS_COMPLEXITY, (D('.71'), D('.61'), D('.35'))))
    AU = dict(zip(AUTHENTICATION, (D('.704'), D('.56'), D('.45'))))
    C = dict(zip(CONFIDENTIALITY, (D('0'), D('.275'), D('.66'))))
    A = I = C

    _AV_MAP = _from_capitals(AV, True)
    _AC_MAP = _from_capitals(AC, True)
    _AU_MAP = _from_capitals(AU, True)
    _C_MAP = _from_capitals(C, True)
    _A_MAP = _I_MAP = _C_MAP

    def __init__(self, access_vector=None, access_complexity=None, authentication=None, confidentiality_impact=None,
                 integrity_impact=None, availability_impact=None):
        self.access_vector = access_vector or self.ACCESS_VECTOR[0]
        self.access_complexity = access_complexity or self.ACCESS_COMPLEXITY[0]
        self.authentication = authentication or self.AUTHENTICATION[0]

        self.confidentiality_impact = confidentiality_impact or self.CONFIDENTIALITY[0]
        self.integrity_impact = integrity_impact or self.INTEGRITY[0]
        self.availability_impact = availability_impact or self.AVAILABILITY[0]

    @property
    def access_vector(self):
        return self._av

    @access_vector.setter
    def access_vector(self, metric):
        try:
            self._av = metric if metric in self.ACCESS_VECTOR else self._AV_MAP[metric.upper()]
        except (AttributeError, KeyError):
            raise CvssMetricError(u'access_vector', metric)

    @property
    def access_complexity(self):
        return self._ac

    @access_complexity.setter
    def access_complexity(self, metric):
        try:
            self._ac = metric if metric in self.ACCESS_COMPLEXITY else self._AC_MAP[metric.upper()]
        except (AttributeError, KeyError):
            raise CvssMetricError(u'access_complexity', metric)

    @property
    def authentication(self):
        return self._au

    @authentication.setter
    def authentication(self, metric):
        try:
            self._au = metric if metric in self.AUTHENTICATION else self._AU_MAP[metric.upper()]
        except (AttributeError, KeyError):
            raise CvssMetricError(u'authentication', metric)

    @property
    def confidentiality_impact(self):
        return self._c

    @confidentiality_impact.setter
    def confidentiality_impact(self, metric):
        try:
            self._c = metric if metric in self.CONFIDENTIALITY else self._C_MAP[metric.upper()]
        except (AttributeError, KeyError):
            raise CvssMetricError(u'confidentiality_impact', metric)

    @property
    def integrity_impact(self):
        return self._i

    @integrity_impact.setter
    def integrity_impact(self, metric):
        try:
            self._i = metric if metric in self.INTEGRITY else self._I_MAP[metric.upper()]
        except (AttributeError, KeyError):
            raise CvssMetricError(u'integrity_impact', metric)

    @property
    def availability_impact(self):
        return self._a

    @availability_impact.setter
    def availability_impact(self, metric):
        try:
            self._a = metric if metric in self.AVAILABILITY else self._A_MAP[metric.upper()]
        except (AttributeError, KeyError):
            raise CvssMetricError(u'availability_impact', metric)

    @property
    def _base_score(self):
        """
        Base Score:
        (.6 * Impact + .4 * Exploitability - 1.5) * (1.176 if Impact else 0)
        """
        f_imp = D('1.176') if self._impact_subscore else D('0')
        return (D('.6') * self._impact_subscore + D('.4') * self._exploitability_subscore - D('1.5')) * f_imp

    @property
    def base_score(self):
        return float(max(D('0'), self._base_score).quantize(ROUND_ONE_PLACE))

    score = base_score

    @property
    def _impact_subscore(self):
        """
        Impact Subscore:
        10.41 * (1 - (1 - ConfImpact) * (1 - IntegImpact) * (1 - AvailImpact))
        """
        c = D('1') - self.C[self.confidentiality_impact]
        i = D('1') - self.I[self.integrity_impact]
        a = D('1') - self.A[self.availability_impact]
        return D('10.41') * (D('1') - c * i * a)

    @property
    def impact_subscore(self):
        return float(max(D('0'), self._impact_subscore).quantize(ROUND_ONE_PLACE))

    @property
    def _exploitability_subscore(self):
        """
        Exploitability Subscore:
        20 * AccessVector * AccessComplexity * Authentication
        """
        return (D('20') * self.AV[self.access_vector] *
                self.AC[self.access_complexity] *
                self.AU[self.authentication])

    @property
    def exploitability_subscore(self):
        return float(max(D('0'), self._exploitability_subscore).quantize(ROUND_ONE_PLACE))

    @property
    def vector(self):
        return (u'AV:{0.access_vector[0]}/'
                u'AC:{0.access_complexity[0]}/'
                u'Au:{0.authentication[0]}/'
                u'C:{0.confidentiality_impact[0]}/'
                u'I:{0.integrity_impact[0]}/'
                u'A:{0.availability_impact[0]}').format(self)

    def copy(self):
        return self.from_vector(self.vector)

    def reset(self):
        self.__init__()

    @classmethod
    def from_vector(cls, vector):
        try:
            return cls(*cls.RE_VECTOR.match(vector).groups())
        except AttributeError:
            raise CvssVectorError(vector)

    def __str__(self):
        return self.vector

    def __lt__(self, other):
        return self.score < other.score

    def __eq__(self, other):
        return self.score == other.score


@total_ordering
class CvssV2Temporal(CvssV2Base):
    RE_VECTOR = re.compile(
        ur'^{0}(?:/{1})?$'.format(CvssV2Base.RE_VECTOR.pattern[1:-1],
                                  ur'E:(?P<E>ND|POC|[UFH])/'
                                  ur'RL:(?P<RL>ND|[OT]F|[WU])/'
                                  ur'RC:(?P<RC>ND|U[CR]|C)'),
        re.IGNORECASE)

    EXPLOITABILITY = u'Not Defined', u'Unproven', u'Proof of Concept', u'Functional', u'High'
    REMEDIATION_LEVEL = u'Not Defined', u'Unavailable', u'Workaround', u'Temporary Fix', u'Official Fix'
    REPORT_CONFIDENCE = u'Not Defined', u'Unconfirmed', u'Uncorroborated', u'Confirmed'

    E = dict(zip(EXPLOITABILITY, (D('1'), D('.85'), D('.9'), D('.95'), D('1'))))
    RL = dict(zip(REMEDIATION_LEVEL, (D('1'), D('1'), D('.95'), D('.9'), D('.87'))))
    RC = dict(zip(REPORT_CONFIDENCE, (D('1'), D('.9'), D('.95'), D('1'))))

    _E_MAP = dict(zip(EXPLOITABILITY, (u'ND', u'U', u'POC', u'F', u'H')))
    _E_MAP.update(_reversed(_E_MAP))
    _RL_MAP = _from_capitals(RL)
    _RC_MAP = dict(zip(REPORT_CONFIDENCE, (u'ND', u'UC', u'UR', u'C')))
    _RC_MAP.update(_reversed(_RC_MAP))

    def __init__(self, access_vector=None, access_complexity=None, authentication=None, confidentiality_impact=None,
                 integrity_impact=None, availability_impact=None, exploitability=None, remediation_level=None,
                 report_confidence=None):
        super(CvssV2Temporal, self).__init__(access_vector, access_complexity, authentication, confidentiality_impact,
                                             integrity_impact, availability_impact)
        self.exploitability = exploitability or self.EXPLOITABILITY[0]
        self.remediation_level = remediation_level or self.REMEDIATION_LEVEL[0]
        self.report_confidence = report_confidence or self.REPORT_CONFIDENCE[0]

    @property
    def exploitability(self):
        return self._e

    @exploitability.setter
    def exploitability(self, metric):
        try:
            self._e = metric if metric in self.EXPLOITABILITY else self._E_MAP[metric.upper()]
        except (AttributeError, KeyError):
            raise CvssMetricError(u'exploitability', metric)

    @property
    def remediation_level(self):
        return self._rl

    @remediation_level.setter
    def remediation_level(self, metric):
        try:
            self._rl = metric if metric in self.REMEDIATION_LEVEL else self._RL_MAP[metric.upper()]
        except (AttributeError, KeyError):
            raise CvssMetricError(u'remediation_level', metric)

    @property
    def report_confidence(self):
        return self._rc

    @report_confidence.setter
    def report_confidence(self, metric):
        try:
            self._rc = metric if metric in self.REPORT_CONFIDENCE else self._RC_MAP[metric.upper()]
        except (AttributeError, KeyError):
            raise CvssMetricError(u'report_confidence', metric)

    @property
    def _temporal_modifier(self):
        """
        Temporal Modifier:
        Exploitability * RemediationLevel * ReportConfidence
        """
        return self.E[self.exploitability] * self.RL[self.remediation_level] * self.RC[self.report_confidence]

    @property
    def temporal_modifier(self):
        return float(max(D('0'), self._temporal_modifier).quantize(ROUND_TWO_PLACES))

    @property
    def _temporal_score(self):
        return self._base_score * self._temporal_modifier

    @property
    def temporal_score(self):
        return float(max(D('0'), self._temporal_score).quantize(ROUND_ONE_PLACE))

    score = temporal_score

    @property
    def vector(self):
        vector = u'E:{0}/RL:{1}/RC:{2}'.format(self._E_MAP[self.exploitability],
                                               self._RL_MAP[self.remediation_level],
                                               self._RC_MAP[self.report_confidence])
        if vector.count(u'ND') == 3:
            return super(CvssV2Temporal, self).vector
        else:
            return u'{0}/{1}'.format(super(CvssV2Temporal, self).vector, vector)


@total_ordering
class CvssV2Environmental(CvssV2Temporal):
    RE_VECTOR = re.compile(ur'^{0}(?:/{1})?$'.format(CvssV2Temporal.RE_VECTOR.pattern[1:-1],
                                                     ur'CDP:(?P<CDP>ND?|LM?|M?H)/'
                                                     ur'TD:(?P<TD>ND?|[LMH])/'
                                                     ur'CR:(?P<CR>ND?|[LMH])/'
                                                     ur'IR:(?P<IR>ND?|[LMH])/'
                                                     ur'AR:(?P<AR>ND?|[LMH])'),
                           re.IGNORECASE)

    COLLATERAL_DAMAGE_POTENTIAL = u'Not Defined', u'None', u'Low', u'Low-Medium', u'Medium-High', u'High'
    TARGET_DISTRIBUTION = u'Not Defined', u'None', u'Low', u'Medium', u'High'
    CONFIDENTIALITY_REQUIREMENT = u'Not Defined', u'Low', u'Medium', u'High'
    AVAILABILITY_REQUIREMENT = INTEGRITY_REQUIREMENT = CONFIDENTIALITY_REQUIREMENT

    CDP = dict(zip(COLLATERAL_DAMAGE_POTENTIAL, (D('0'), D('0'), D('.1'), D('.3'), D('.4'), D('.5'))))
    TD = dict(zip(TARGET_DISTRIBUTION, (D('1'), D('0'), D('.25'), D('.75'), D('1'))))
    CR = dict(zip(CONFIDENTIALITY_REQUIREMENT, (D('1'), D('.5'), D('1'), D('1.51'))))
    AR = IR = CR

    _CDP_MAP = _from_capitals(CDP)
    _TD_MAP = _from_capitals(TD)
    _CR_MAP = _from_capitals(CR)
    _AR_MAP = _IR_MAP = _CR_MAP

    def __init__(self, access_vector=None, access_complexity=None, authentication=None, confidentiality_impact=None,
                 integrity_impact=None, availability_impact=None, exploitability=None, remediation_level=None,
                 report_confidence=None, collateral_damage_potential=None, target_distribution=None,
                 confidentiality_requirement=None, integrity_requirement=None, availability_requirement=None):
        super(CvssV2Environmental, self).__init__(access_vector, access_complexity, authentication,
                                                  confidentiality_impact, integrity_impact, availability_impact,
                                                  exploitability, remediation_level, report_confidence)
        self.collateral_damage_potential = collateral_damage_potential or self.COLLATERAL_DAMAGE_POTENTIAL[0]
        self.target_distribution = target_distribution or self.TARGET_DISTRIBUTION[0]

        self.confidentiality_requirement = confidentiality_requirement or self.CONFIDENTIALITY_REQUIREMENT[0]
        self.integrity_requirement = integrity_requirement or self.INTEGRITY_REQUIREMENT[0]
        self.availability_requirement = availability_requirement or self.AVAILABILITY_REQUIREMENT[0]

    @property
    def collateral_damage_potential(self):
        return self._cdp

    @collateral_damage_potential.setter
    def collateral_damage_potential(self, metric):
        try:
            self._cdp = metric if metric in self.COLLATERAL_DAMAGE_POTENTIAL else self._CDP_MAP[metric.upper()]
        except (AttributeError, KeyError):
            raise CvssMetricError(u'collateral_damage_potential', metric)

    @property
    def target_distribution(self):
        return self._td

    @target_distribution.setter
    def target_distribution(self, metric):
        try:
            self._td = metric if metric in self.TARGET_DISTRIBUTION else self._TD_MAP[metric.upper()]
        except (AttributeError, KeyError):
            raise CvssMetricError(u'target_distribution', metric)

    @property
    def confidentiality_requirement(self):
        return self._cr

    @confidentiality_requirement.setter
    def confidentiality_requirement(self, metric):
        try:
            self._cr = metric if metric in self.CONFIDENTIALITY_REQUIREMENT else self._CR_MAP[metric.upper()]
        except (AttributeError, KeyError):
            raise CvssMetricError(u'confidentiality_requirement', metric)

    @property
    def integrity_requirement(self):
        return self._ir

    @integrity_requirement.setter
    def integrity_requirement(self, metric):
        try:
            self._ir = metric if metric in self.INTEGRITY_REQUIREMENT else self._IR_MAP[metric.upper()]
        except (AttributeError, KeyError):
            raise CvssMetricError(u'integrity_requirement', metric)

    @property
    def availability_requirement(self):
        return self._ar

    @availability_requirement.setter
    def availability_requirement(self, metric):
        try:
            self._ar = metric if metric in self.AVAILABILITY_REQUIREMENT else self._AR_MAP[metric.upper()]
        except (AttributeError, KeyError):
            raise CvssMetricError(u'target_distribution', metric)

    @property
    def _environmental_score(self):
        """
        Environmental Score:
        (ModifiedTemporal + (10 - ModifiedTemporal) * CollateralDamagePotential) * TargetDistribution
        """
        modified_temporal = self._modified_base_score * self._temporal_modifier
        return ((modified_temporal + (D('10') - modified_temporal) * self.CDP[self.collateral_damage_potential]) *
                self.TD[self.target_distribution])

    @property
    def environmental_score(self):
        return float(max(D('0'), self._environmental_score).quantize(ROUND_ONE_PLACE))

    score = environmental_score

    @property
    def _modified_base_score(self):
        """
        Modified Base Score:
        (.6 * ModifiedImpact + .4 * Exploitability - 1.5) * (1.176 if Impact else 0)
        """
        f_imp = D('1.176') if self._modified_impact_subscore else D('0')
        return (D('.6') * self._modified_impact_subscore + D('.4') * self._exploitability_subscore - D('1.5')) * f_imp

    @property
    def modified_base_score(self):
        return float(max(D('0'), self._modified_base_score).quantize(ROUND_ONE_PLACE))

    @property
    def _modified_impact_subscore(self):
        """
        Modified Impact Subscore:
        10.41 * (1 - (1 - ConfImpact * ConfReq) * \
        (1 - IntegImpact * IntegReq) * (1 - AvailImpact * AvailReq))
        """
        c = D('1') - (self.C[self.confidentiality_impact] * self.CR[self.confidentiality_requirement])
        i = D('1') - (self.I[self.integrity_impact] * self.IR[self.integrity_requirement])
        a = D('1') - (self.A[self.availability_impact] * self.AR[self.availability_requirement])
        return min(D('10'), (D('10.41') * (D('1') - c * i * a)))

    @property
    def modified_impact_subscore(self):
        return float(max(D('0'), self._modified_impact_subscore).quantize(ROUND_ONE_PLACE))

    @property
    def vector(self):
        vector = u'CDP:{0}/TD:{1}/CR:{2}/IR:{3}/AR:{4}'.format(self._CDP_MAP[self.collateral_damage_potential],
                                                               self._TD_MAP[self.target_distribution],
                                                               self._CR_MAP[self.confidentiality_requirement],
                                                               self._IR_MAP[self.integrity_requirement],
                                                               self._AR_MAP[self.availability_requirement])
        if vector.count(u'ND') == 5:
            return super(CvssV2Environmental, self).vector
        else:
            return u'{0}/{1}'.format(super(CvssV2Environmental, self).vector, vector)


Cvss = CvssV2 = CvssV2Environmental
