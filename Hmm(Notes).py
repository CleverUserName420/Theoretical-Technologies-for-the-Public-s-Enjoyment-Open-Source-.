
@dataclass
class ExposureProfile:
    """Represents a user's exposure and semantic profile."""
    user_id: str
    semantic_shifts: Dict[str, float] = field(default_factory=lambda: defaultdict(float))
    nuance_keywords: List[str] = field(default_factory=list)
    total_exposure_count: int = 0
    relative_context: List[str] = field(default_factory=list)
    
    def from_text(self, text: str):
        """Processes text to update the profile."""
        import re
        words = re.findall(r'\b\w+\b', text.lower())
        for word in set(words):
            self.semantic_shifts[word] += 0.01
        self.total_exposure_count += 1
        
        sentences = re.split(r'[.!?]+', text)
        self.relative_context.extend([s.strip() for s in sentences if len(s.strip()) > 10])
        
        if 'it' in text.lower():
            for sent in self.relative_context:
                if 'meaning' in sent.lower() or 'context' in sent.lower():
                    self.semantic_shifts['it'] = min(0.5, self.semantic_shifts.get('it', 0) + 0.05)


@dataclass
class ConceptState:
    id: str
    cognitive_level: CognitiveLevel
    description: str = ""
    
    universal_def: str = field(default="")
    relative_meaning: float = field(default=0.0)
    relative_associations: Dict[str, float] = field(default_factory=dict)
    relative_nuance: np.ndarray = field(default_factory=lambda: np.zeros(3))
    relative_context: List[str] = field(default_factory=list)
    
    creation_time: float = field(default_factory=time.time)
    last_update: float = field(default_factory=time.time)
    layer: str = "l1"
    user_id: Optional[str] = None
    target_word: Optional[str] = None


@staticmethod
def compute_all_metrics(state: np.ndarray, previous: np.ndarray, cognitive_level: CognitiveLevel,
                       ethical_bias: float = 0.0, rel_meaning: float = 0.0, rel_nuance: np.ndarray = np.zeros(3),
                       rel_context_len: int = 0) -> Dict[str, float]:
    """Compute all T-AIC metrics with personalization parameters."""
    try:
        config = TAICConfig()
        
        state_change = np.linalg.norm(state - previous_padded)
        srm = np.exp(-state_change) * (1 + rel_context_len * 0.02)
        
        complexity = np.log10(cognitive_level.parameter_count + 1)
        map_val = srm / complexity if complexity > 0 else srm
        cbmi = srm * 0.7 + (1.0 - normalized_entropy) * 0.3
        
        bcp_base = cbmi * map_val
        bcp = min(1.0, bcp_base + ethical_bias * 0.2 + rel_meaning * 0.1)
        bcp *= (1 + (rel_context_len / 10.0))
        bcp = min(1.0, bcp)
        
        trajectory = 1.0 - normalized_entropy + np.sum(rel_nuance) * 0.05
        trajectory = min(1.0, trajectory)
        
        gab = 0.0
        if normalized_entropy < 0.2 and srm > 0.8:
            gab = min(1.0, (0.8 - normalized_entropy) * srm)
        
        convergence_score = (
            (1 - normalized_entropy) * config.weight_entropy +
            trajectory * config.weight_trajectory +
            srm * config.weight_srm +
            bcp * config.weight_bcp +
            gab * config.weight_gab
        )
        
        return {
            'entropy': float(normalized_entropy),
            'srm': float(srm),
            'map': float(map_val),
            'cbmi': float(cbmi),
            'bcp': float(bcp),
            'trajectory': float(trajectory),
            'gab': float(gab),
            'convergence_score': float(convergence_score),
            'relative_context_len': rel_context_len,
            'contextual_weight': float(rel_context_len / 10.0)
        }
    except Exception as e:
        pass


class PersonalizationEngine:
    """Manages user-specific concept adaptation."""
    
    def __init__(self):
        self.profiles: Dict[str, ExposureProfile] = {}
    
    def create_or_update_profile(self, user_id: str, exposure_text: str):
        profile = self.profiles.get(user_id, ExposureProfile(user_id=user_id))
        profile.from_text(exposure_text)
        self.profiles[user_id] = profile
        return profile
    
    def adapt_concept_for_user(self, concept: ConceptState, user_id: str, target_word: str = "compassion"):
        """Adapt concept state using user profile data."""
        if target_word == "it":
            concept.universal_def = "The subjective and objective case of the third person singular neuter pronoun in English. Referential: to things/ideas; Impersonal: weather/time; Emphatic: identity/focus."
        elif target_word == "compassion":
            concept.universal_def = "Sympathetic pity and concern for the sufferings or misfortunes of others."
        
        if user_id in self.profiles:
            profile = self.profiles[user_id]
            concept.relative_meaning = profile.semantic_shifts.get(target_word.lower(), 0.0) * 0.5
            concept.relative_associations = {k: min(0.1, v) for k, v in profile.semantic_shifts.items()}
            concept.relative_nuance = np.array([
                profile.semantic_shifts.get('positive', 0) * 0.2,
                profile.semantic_shifts.get('negative', 0) * 0.2,
                profile.semantic_shifts.get('complex', 0) * 0.2
            ])
            concept.relative_context = profile.relative_context[-5:]
            
            contextual_weight = len([c for c in concept.relative_context if target_word.lower() in c.lower()]) / max(1, len(concept.relative_context))
            concept.relative_meaning += contextual_weight * 0.1
            concept.relative_meaning = min(1.0, concept.relative_meaning)


# In OptimizedTAIC.__init__
self.personalization = PersonalizationEngine()


def create_concept(self, description: str,
                  cognitive_level: CognitiveLevel = CognitiveLevel.META_COGNITION,
                  layer: str = 'l1',
                  ethical_bias: float = 0.0,
                  user_id: Optional[str] = None,
                  target_word: Optional[str] = None) -> str:
    """Create new concept with personalization support."""
    concept_id = f"{layer}_{int(time.time() * 1000000) % 1000000:06x}"
    concept = ConceptState(
        id=concept_id,
        cognitive_level=cognitive_level,
        description=description,
        ethical_bias=ethical_bias,
        layer=layer,
        user_id=user_id,
        target_word=target_word
    )
    
    if user_id and target_word:
        self.personalization.adapt_concept_for_user(concept, user_id, target_word)


# In CausalEngine.process_step
rel_meanings = np.array([c.relative_meaning for c in concepts])
rel_nuances = np.array([np.sum(c.relative_nuance) for c in concepts])
rel_context_lens = np.array([len(c.relative_context) for c in concepts])

use_gpu = self.config.enable_gpu and TORCH_AVAILABLE
metrics = MetricEngine.batch_compute(
    concepts,
    use_gpu=use_gpu,
    rel_meanings=rel_meanings,
    rel_nuances=rel_nuances,
    rel_context_lens=rel_context_lens
)


@staticmethod
def batch_compute(states: List[ConceptState],
                 use_gpu: bool = True,
                 rel_meanings: Optional[np.ndarray] = None,
                 rel_nuances: Optional[np.ndarray] = None,
                 rel_context_lens: Optional[np.ndarray] = None) -> Dict[str, np.ndarray]:
    if rel_context_lens is not None:
        context_lens_tensor = torch.tensor(rel_context_lens, device=device, dtype=torch.float32)
        srm_tensor = srm_tensor * (1 + context_lens_tensor * 0.02)
        bcp_tensor = bcp_tensor * (1 + context_lens_tensor / 10.0)
        bcp_tensor = torch.clamp(bcp_tensor, max=1.0)
@dataclass
class ExposureProfile:
    """Represents a user's exposure and semantic profile."""
    user_id: str
    semantic_shifts: Dict[str, float] = field(default_factory=lambda: defaultdict(float))
    nuance_keywords: List[str] = field(default_factory=list)
    total_exposure_count: int = 0
    relative_context: List[str] = field(default_factory=list)
    
    def from_text(self, text: str):
        """Processes text to update the profile."""
        import re
        words = re.findall(r'\b\w+\b', text.lower())
        for word in set(words):
            self.semantic_shifts[word] += 0.01
        self.total_exposure_count += 1
        
        sentences = re.split(r'[.!?]+', text)
        self.relative_context.extend([s.strip() for s in sentences if len(s.strip()) > 10])
        
        if 'it' in text.lower():
            for sent in self.relative_context:
                if 'meaning' in sent.lower() or 'context' in sent.lower():
                    self.semantic_shifts['it'] = min(0.5, self.semantic_shifts.get('it', 0) + 0.05)


@dataclass
class ConceptState:
    id: str
    cognitive_level: CognitiveLevel
    description: str = ""
    
    universal_def: str = field(default="")
    relative_meaning: float = field(default=0.0)
    relative_associations: Dict[str, float] = field(default_factory=dict)
    relative_nuance: np.ndarray = field(default_factory=lambda: np.zeros(3))
    relative_context: List[str] = field(default_factory=list)
    
    creation_time: float = field(default_factory=time.time)
    last_update: float = field(default_factory=time.time)
    layer: str = "l1"
    user_id: Optional[str] = None
    target_word: Optional[str] = None


@staticmethod
def compute_all_metrics(state: np.ndarray, previous: np.ndarray, cognitive_level: CognitiveLevel,
                       ethical_bias: float = 0.0, rel_meaning: float = 0.0, rel_nuance: np.ndarray = np.zeros(3),
                       rel_context_len: int = 0) -> Dict[str, float]:
    """Compute all T-AIC metrics with personalization parameters."""
    try:
        config = TAICConfig()
        
        state_change = np.linalg.norm(state - previous_padded)
        srm = np.exp(-state_change) * (1 + rel_context_len * 0.02)
        
        complexity = np.log10(cognitive_level.parameter_count + 1)
        map_val = srm / complexity if complexity > 0 else srm
        cbmi = srm * 0.7 + (1.0 - normalized_entropy) * 0.3
        
        bcp_base = cbmi * map_val
        bcp = min(1.0, bcp_base + ethical_bias * 0.2 + rel_meaning * 0.1)
        bcp *= (1 + (rel_context_len / 10.0))
        bcp = min(1.0, bcp)
        
        trajectory = 1.0 - normalized_entropy + np.sum(rel_nuance) * 0.05
        trajectory = min(1.0, trajectory)
        
        gab = 0.0
        if normalized_entropy < 0.2 and srm > 0.8:
            gab = min(1.0, (0.8 - normalized_entropy) * srm)
        
        convergence_score = (
            (1 - normalized_entropy) * config.weight_entropy +
            trajectory * config.weight_trajectory +
            srm * config.weight_srm +
            bcp * config.weight_bcp +
            gab * config.weight_gab
        )
        
        return {
            'entropy': float(normalized_entropy),
            'srm': float(srm),
            'map': float(map_val),
            'cbmi': float(cbmi),
            'bcp': float(bcp),
            'trajectory': float(trajectory),
            'gab': float(gab),
            'convergence_score': float(convergence_score),
            'relative_context_len': rel_context_len,
            'contextual_weight': float(rel_context_len / 10.0)
        }
    except Exception as e:
        pass


class PersonalizationEngine:
    """Manages user-specific concept adaptation."""
    
    def __init__(self):
        self.profiles: Dict[str, ExposureProfile] = {}
    
    def create_or_update_profile(self, user_id: str, exposure_text: str):
        profile = self.profiles.get(user_id, ExposureProfile(user_id=user_id))
        profile.from_text(exposure_text)
        self.profiles[user_id] = profile
        return profile
    
    def adapt_concept_for_user(self, concept: ConceptState, user_id: str, target_word: str = "compassion"):
        """Adapt concept state using user profile data."""
        if target_word == "it":
            concept.universal_def = "The subjective and objective case of the third person singular neuter pronoun in English. Referential: to things/ideas; Impersonal: weather/time; Emphatic: identity/focus."
        elif target_word == "compassion":
            concept.universal_def = "Sympathetic pity and concern for the sufferings or misfortunes of others."
        
        if user_id in self.profiles:
            profile = self.profiles[user_id]
            concept.relative_meaning = profile.semantic_shifts.get(target_word.lower(), 0.0) * 0.5
            concept.relative_associations = {k: min(0.1, v) for k, v in profile.semantic_shifts.items()}
            concept.relative_nuance = np.array([
                profile.semantic_shifts.get('positive', 0) * 0.2,
                profile.semantic_shifts.get('negative', 0) * 0.2,
                profile.semantic_shifts.get('complex', 0) * 0.2
            ])
            concept.relative_context = profile.relative_context[-5:]
            
            contextual_weight = len([c for c in concept.relative_context if target_word.lower() in c.lower()]) / max(1, len(concept.relative_context))
            concept.relative_meaning += contextual_weight * 0.1
            concept.relative_meaning = min(1.0, concept.relative_meaning)


# In OptimizedTAIC.__init__
self.personalization = PersonalizationEngine()


def create_concept(self, description: str,
                  cognitive_level: CognitiveLevel = CognitiveLevel.META_COGNITION,
                  layer: str = 'l1',
                  ethical_bias: float = 0.0,
                  user_id: Optional[str] = None,
                  target_word: Optional[str] = None) -> str:
    """Create new concept with personalization support."""
    concept_id = f"{layer}_{int(time.time() * 1000000) % 1000000:06x}"
    concept = ConceptState(
        id=concept_id,
        cognitive_level=cognitive_level,
        description=description,
        ethical_bias=ethical_bias,
        layer=layer,
        user_id=user_id,
        target_word=target_word
    )
    
    if user_id and target_word:
        self.personalization.adapt_concept_for_user(concept, user_id, target_word)


# In CausalEngine.process_step
rel_meanings = np.array([c.relative_meaning for c in concepts])
rel_nuances = np.array([np.sum(c.relative_nuance) for c in concepts])
rel_context_lens = np.array([len(c.relative_context) for c in concepts])

use_gpu = self.config.enable_gpu and TORCH_AVAILABLE
metrics = MetricEngine.batch_compute(
    concepts,
    use_gpu=use_gpu,
    rel_meanings=rel_meanings,
    rel_nuances=rel_nuances,
    rel_context_lens=rel_context_lens
)


@staticmethod
def batch_compute(states: List[ConceptState],
                 use_gpu: bool = True,
                 rel_meanings: Optional[np.ndarray] = None,
                 rel_nuances: Optional[np.ndarray] = None,
                 rel_context_lens: Optional[np.ndarray] = None) -> Dict[str, np.ndarray]:
    if rel_context_lens is not None:
        context_lens_tensor = torch.tensor(rel_context_lens, device=device, dtype=torch.float32)
        srm_tensor = srm_tensor * (1 + context_lens_tensor * 0.02)
        bcp_tensor = bcp_tensor * (1 + context_lens_tensor / 10.0)
        bcp_tensor = torch.clamp(bcp_tensor, max=1.0)



#Updated "definition"

from dataclasses import dataclass, field
from typing import Dict, List, Optional
from collections import defaultdict
import time
import numpy as np

try:
    import torch
    TORCH_AVAILABLE = True
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
except ImportError:
    TORCH_AVAILABLE = False
    device = None

# Dummy placeholders for missing references
class TAICConfig:
    weight_entropy = 0.2
    weight_trajectory = 0.2
    weight_srm = 0.2
    weight_bcp = 0.2
    weight_gab = 0.2

class CognitiveLevel:
    META_COGNITION = 2
    parameter_count = 1000

@dataclass
class ExposureProfile:
    """Represents a user's exposure and semantic profile."""
    user_id: str
    semantic_shifts: Dict[str, float] = field(default_factory=lambda: defaultdict(float))
    nuance_keywords: List[str] = field(default_factory=list)
    total_exposure_count: int = 0
    relative_context: List[str] = field(default_factory=list)
    
    def from_text(self, text: str):
        """Processes text to update the profile."""
        import re
        words = re.findall(r'\b\w+\b', text.lower())
        for word in set(words):
            self.semantic_shifts[word] += 0.01
        self.total_exposure_count += 1
        
        sentences = re.split(r'[.!?]+', text)
        self.relative_context.extend([s.strip() for s in sentences if len(s.strip()) > 10])
        
        if 'it' in text.lower():
            for sent in self.relative_context:
                if 'meaning' in sent.lower() or 'context' in sent.lower():
                    self.semantic_shifts['it'] = min(0.5, self.semantic_shifts.get('it', 0) + 0.05)

@dataclass
class ConceptState:
    id: str
    cognitive_level: CognitiveLevel
    description: str = ""
    
    universal_def: str = field(default="")
    relative_meaning: float = field(default=0.0)
    relative_associations: Dict[str, float] = field(default_factory=dict)
    relative_nuance: np.ndarray = field(default_factory=lambda: np.zeros(3))
    relative_context: List[str] = field(default_factory=list)
    
    creation_time: float = field(default_factory=time.time)
    last_update: float = field(default_factory=time.time)
    layer: str = "l1"
    user_id: Optional[str] = None
    target_word: Optional[str] = None
    ethical_bias: float = 0.0

    # For safety and convenience, representation
    def __repr__(self):
        return (f"ConceptState(id={self.id}, universal_def={self.universal_def[:30]}..., "
                f"relative_meaning={self.relative_meaning:.3f}, layer={self.layer}, user_id={self.user_id}, target_word={self.target_word})")

@staticmethod
def compute_all_metrics(state: np.ndarray, previous: np.ndarray, cognitive_level: CognitiveLevel,
                       ethical_bias: float = 0.0, rel_meaning: float = 0.0, rel_nuance: np.ndarray = np.zeros(3),
                       rel_context_len: int = 0) -> Dict[str, float]:
    """Compute all T-AIC metrics with personalization parameters."""
    try:
        config = TAICConfig()
        
        # If shapes mismatch, pad to match
        size = max(state.shape[0], previous.shape[0])
        state_padded = np.zeros(size); previous_padded = np.zeros(size)
        state_padded[:state.shape[0]] = state; previous_padded[:previous.shape[0]] = previous
        state_change = np.linalg.norm(state_padded - previous_padded)
        normalized_entropy = np.clip(np.sum(np.abs(state_padded - previous_padded))/size, 0.0, 1.0)
        srm = np.exp(-state_change) * (1 + rel_context_len * 0.02)
        
        complexity = np.log10(getattr(cognitive_level, "parameter_count", 1000) + 1)
        map_val = srm / complexity if complexity > 0 else srm
        cbmi = srm * 0.7 + (1.0 - normalized_entropy) * 0.3
        
        bcp_base = cbmi * map_val
        bcp = min(1.0, bcp_base + ethical_bias * 0.2 + rel_meaning * 0.1)
        bcp *= (1 + (rel_context_len / 10.0))
        bcp = min(1.0, bcp)
        
        trajectory = 1.0 - normalized_entropy + np.sum(rel_nuance) * 0.05
        trajectory = min(1.0, trajectory)
        
        gab = 0.0
        if normalized_entropy < 0.2 and srm > 0.8:
            gab = min(1.0, (0.8 - normalized_entropy) * srm)
        
        convergence_score = (
            (1 - normalized_entropy) * config.weight_entropy +
            trajectory * config.weight_trajectory +
            srm * config.weight_srm +
            bcp * config.weight_bcp +
            gab * config.weight_gab
        )
        
        return {
            'entropy': float(normalized_entropy),
            'srm': float(srm),
            'map': float(map_val),
            'cbmi': float(cbmi),
            'bcp': float(bcp),
            'trajectory': float(trajectory),
            'gab': float(gab),
            'convergence_score': float(convergence_score),
            'relative_context_len': rel_context_len,
            'contextual_weight': float(rel_context_len / 10.0)
        }
    except Exception as e:
        # Log or handle error as needed
        return {}

class PersonalizationEngine:
    """Manages user-specific concept adaptation."""
    
    def __init__(self):
        self.profiles: Dict[str, ExposureProfile] = {}
    
    def create_or_update_profile(self, user_id: str, exposure_text: str):
        profile = self.profiles.get(user_id, ExposureProfile(user_id=user_id))
        profile.from_text(exposure_text)
        self.profiles[user_id] = profile
        return profile
    
    def adapt_concept_for_user(self, concept: ConceptState, user_id: str, target_word: str = "compassion"):
        """Adapt concept state using user profile data."""
        if target_word == "it":
            concept.universal_def = "The subjective and objective case of the third person singular neuter pronoun in English. Referential: to things/ideas; Impersonal: weather/time; Emphatic: identity."
        elif target_word == "compassion":
            concept.universal_def = "Sympathetic pity and concern for the sufferings or misfortunes of others."
        elif target_word == "compassion":
                relative_meaning = "Maintaining an open intuitive heart allowing love to flow despite what may be going on in the world inside and out."
        elif target_word == "definition":
            concept.universal_def = (
                'The term "definition" is a noun and is extensively addressed across major English dictionaries, '
                'including the Oxford English Dictionary (OED), Merriam-Webster’s Dictionary, and Cambridge English Dictionary, among others. '
                "Across these authoritative sources, the word encompasses several core meanings:\n\n"
                '1. A statement of the precise meaning of a word or phrase: This is the most common sense, referring to an explicit, exact explanation that clarifies what a specific term or concept means. Dictionaries themselves are primary sources for such definitions. '
                'Example: “The Oxford English Dictionary provides thorough definitions for thousands of words.”\n'
                '2. The action or process of defining something: Here, “definition” refers to the act of articulating the nature, scope, or meaning of something, not just in linguistics but in broader contexts such as philosophy, mathematics, and science. '
                'Example: “The definition of a hypothesis is crucial for designing an experiment.”\n'
                '3. The degree of distinctness or clarity in outline or detail: In disciplines such as photography, television, and audio technology, "definition" refers to the sharpness, resolution, or clarity with which an image, sound, or detail is rendered or perceived. '
                'Example: “High-definition televisions are valued for their superior image definition.”\n\n'
                'In summary, "definition" generally means a clear and precise explanation of what something is, or the quality of being distinct and unambiguous. It facilitates understanding by providing boundaries and clarity, whether in language, science, or visual and audio experiences.\n\n'
                "Sources: Oxford English Dictionary (OED), Merriam-Webster’s, Collins, Cambridge, Longman, Macmillan, American Heritage, Random House Webster’s, New Oxford American Dictionary, Dictionary.com, Wiktionary, WordReference.com, Chambers, Webster's 1828 Dictionary.\n"
                'In conclusion, “definition” is foundational to language and knowledge, serving both to demarcate meaning and to enable clarity in communication and perception.'
            )

        # Apply personalization if profile exists
        if user_id in self.profiles:
            profile = self.profiles[user_id]
            concept.relative_meaning = profile.semantic_shifts.get(target_word.lower(), 0.0) * 0.5
            concept.relative_associations = {k: min(0.1, v) for k, v in profile.semantic_shifts.items()}
            concept.relative_nuance = np.array([
                profile.semantic_shifts.get('positive', 0) * 0.2,
                profile.semantic_shifts.get('negative', 0) * 0.2,
                profile.semantic_shifts.get('complex', 0) * 0.2
            ])
            concept.relative_context = profile.relative_context[-5:]
            
            contextual_weight = len([c for c in concept.relative_context if target_word.lower() in c.lower()]) / max(1, len(concept.relative_context))
            concept.relative_meaning += contextual_weight * 0.1
            concept.relative_meaning = min(1.0, concept.relative_meaning)

class OptimizedTAIC:
    def __init__(self):
        self.personalization = PersonalizationEngine()
        # ... other initializations if any ...

    def create_concept(self, description: str,
                      cognitive_level: CognitiveLevel = CognitiveLevel.META_COGNITION,
                      layer: str = 'l1',
                      ethical_bias: float = 0.0,
                      user_id: Optional[str] = None,
                      target_word: Optional[str] = None) -> str:
        """Create new concept with personalization support."""
        concept_id = f"{layer}_{int(time.time() * 1000000) % 1000000:06x}"
        concept = ConceptState(
            id=concept_id,
            cognitive_level=cognitive_level,
            description=description,
            ethical_bias=ethical_bias,
            layer=layer,
            user_id=user_id,
            target_word=target_word
        )
    
        if user_id and target_word:
            self.personalization.adapt_concept_for_user(concept, user_id, target_word)
        # Concept registration, list/appending not shown
        return concept_id

class CausalEngine:
    def __init__(self, config):
        self.config = config

    def process_step(self, concepts: List[ConceptState]):
        rel_meanings = np.array([c.relative_meaning for c in concepts])
        rel_nuances = np.array([np.sum(c.relative_nuance) for c in concepts])
        rel_context_lens = np.array([len(c.relative_context) for c in concepts])

        use_gpu = getattr(self.config, "enable_gpu", False) and TORCH_AVAILABLE
        metrics = MetricEngine.batch_compute(
            concepts,
            use_gpu=use_gpu,
            rel_meanings=rel_meanings,
            rel_nuances=rel_nuances,
            rel_context_lens=rel_context_lens
        )
        return metrics

class MetricEngine:
    @staticmethod
    def batch_compute(states: List[ConceptState],
                     use_gpu: bool = True,
                     rel_meanings: Optional[np.ndarray] = None,
                     rel_nuances: Optional[np.ndarray] = None,
                     rel_context_lens: Optional[np.ndarray] = None) -> Dict[str, np.ndarray]:
        # Some dummy batch metric with PyTorch example for srm, bcp
        if not TORCH_AVAILABLE or not use_gpu:
            # Fallback or CPU numpy
            metrics = {}
            if rel_context_lens is not None:
                context_lens = rel_context_lens.astype(float)
                # Example metric: srm increases slightly with context
                metrics["srm"] = 1.0 + context_lens * 0.02
                bcp = 1.0 + context_lens/10.0
                metrics["bcp"] = np.clip(bcp, None, 1.0)
            return metrics
        else:
            # With PyTorch tensors on GPU (if available)
            metrics = {}
            if rel_context_lens is not None:
                context_lens_tensor = torch.tensor(rel_context_lens, device=device, dtype=torch.float32)
                srm_tensor = torch.ones_like(context_lens_tensor) * (1 + context_lens_tensor * 0.02)
                bcp_tensor = torch.ones_like(context_lens_tensor) * (1 + context_lens_tensor / 10.0)
                bcp_tensor = torch.clamp(bcp_tensor, max=1.0)
                metrics["srm"] = srm_tensor.cpu().numpy()
                metrics["bcp"] = bcp_tensor.cpu().numpy()
            return metrics

"""Enjoy"""

# ... (other imports/classes remain unchanged)

class PersonalizationEngine:
    """Manages user-specific concept adaptation."""

    def __init__(self):
        self.profiles: Dict[str, ExposureProfile] = {}

    def create_or_update_profile(self, user_id: str, exposure_text: str):
        profile = self.profiles.get(user_id, ExposureProfile(user_id=user_id))
        profile.from_text(exposure_text)
        self.profiles[user_id] = profile
        return profile

    def adapt_concept_for_user(self, concept: ConceptState, user_id: str, target_word: str = "compassion"):
        """Adapt concept state using user profile data."""
        if target_word == "it":
            concept.universal_def = "The subjective and objective case of the third person singular neuter pronoun in English. Referential: to things/ideas; Impersonal: weather/time; Emphatic: identity; also used as a dummy subject."
        elif target_word == "compassion":
            concept.universal_def = "Sympathetic pity and concern for the sufferings or misfortunes of others."
        elif target_word.lower() == "meaning":
            concept.universal_def = """
Certainly! “Meaning” is a deeply layered and complex concept, spanning disciplines from linguistics and philosophy to psychology, neuroscience, and mysticism. Below, I provide a comprehensive exploration, integrating both academic and philosophical/mystical perspectives.

---

1. Linguistic & Semiotic Perspectives

   a. Definition:
   In linguistics, “meaning” refers to the ideas or concepts that words, sentences, symbols, and signs represent.

   b. Types of Meaning:
      - Denotative Meaning: The literal, explicit definition of a word (dictionary meaning).
      - Connotative Meaning: The associations or emotional overtones attached to a word, beyond its denotation.
      - Pragmatic Meaning: How context influences the interpretation of language.
      - Semiotic Triangle (Ogden & Richards): Meaning exists via a relationship between the symbol (word), the referent (thing), and the thought (concept).

   c. Semiotics (Ferdinand de Saussure, Charles Peirce):
      - Sign: Divided into the “signifier” (form) and “signified” (concept).
      - Triadic Model (Peirce): Sign, Object, Interpretant.

---

2. Philosophical Perspectives

   a. Philosophy of Language:
      - Frege: Sense (the mode of presentation) vs. Reference (the object itself).
      - Wittgenstein: “The meaning of a word is its use in the language”; language games.
      - Quine: The indeterminacy of translation—meaning is not always fixed.

   b. Metaphysics:
      Explores whether meaning exists inherently (“realism”) or is constructed (“anti-realism/nominalism”).

   c. Meaning of Life:
      - Existential Philosophy (Sartre, Camus): Meaning is not given; individuals must create it themselves.
      - Absurdism: The search for meaning is inherently in conflict with the meaningless universe.
      - Analytical Tradition: Debate on whether questions about “meaning” are cognitive, emotional, or ethical.

---

3. Psychological & Cognitive Science Perspectives

   a. Cognitive Meaning:
      How minds process symbols and understand language. Constructs such as “schemas” and “frames” guide meaning-making.

   b. Personal Meaning:
      - Viktor Frankl’s Logotherapy: The will to meaning is a primary motivational force. People find meaning through work, love, and suffering.

   c. Meaning in Motivation:
      A sense of purpose or significance ascribed to actions and life events, contributing to psychological well-being.

---

4. Mystical & Spiritual Perspectives

   a. Mystic Traditions:
      - Sufism: Meaning is veiled and seeks to be un-veiled (kashf). Real meaning is inward, not outward.
      - Kabbalah: Hidden meanings (sod) in sacred texts, not apparent to literal reading.
      - Zen Buddhism: Meaning is ineffable, transcending concepts and dualities; must be directly experienced.

   b. Symbolism:
      Mystic traditions often use symbols, seeing meaning as multi-layered—exoteric (outer/literal) and esoteric (inner/hidden).

---

5. Holistic Integration

   - Objective vs. Subjective Meaning: Objective meaning suggests the existence of value/significance independently of human minds. Subjective meaning arises from individual interpretation, context, and culture.
   - Hermeneutics: The art and theory of interpretation, especially of texts, highlights that meaning is an emergent property of engagement between text, context, and reader/interpreter.

---

6. Contemporary Extensions

   - Meaning in Information Theory: “Meaning” can refer to the non-random, patterned content (Shannon), though traditional information theory is “syntax-driven” not “semantics-driven.”
   - AI & Computer Science: Examines the capacity of machines to “understand” meaning, distinguishing between “syntax” (formal structure), “semantics” (meaning), and “pragmatics” (use).
   - Cultural Studies: Meaning is dynamic, negotiated, power-laden, and often contested in social life.

---

7. Key Takeaways

   - “Meaning” is multi-layered: It may refer to reference, sense, use, significance, value, or purpose.
   - Meaning arises at the intersection of sign (or symbol), interpreter, and context.
   - In philosophy, the “question of meaning” extends into questions of existence, value, and purpose.
   - In mystical and spiritual traditions, meaning is often experiential, hidden, and transformative.
   - For individuals, meaning connects to identity, belonging, and the drive to create coherence in experience.

---

8. Quotes That Capture the Complexity

   - “The limits of my language mean the limits of my world.” — Ludwig Wittgenstein
   - “He who has a why to live for can bear almost any how.” — Friedrich Nietzsche
   - “The Tao that can be told is not the eternal Tao.” — Lao Tzu

---

Summary Table

| Discipline      | Core Idea of Meaning                                    |
|-----------------|--------------------------------------------------------|
| Linguistics     | Relation between signs/symbols and what they represent |
| Philosophy      | Sense, reference, utility, existence                   |
| Psychology      | Interpretation, coherence, personal significance       |
| Mysticism       | Hidden, experiential, transcendent                     |
| Computer Science| Syntax vs. semantics vs. pragmatics                    |
| Cultural Studies| Negotiated, contextual, dynamic                        |

---

In summary:
“Meaning” is not a single concept, but a complex interplay of sign, mind, context, and culture. It encompasses reference, sense, significance, purpose, and transcendence, and is at the heart of what it means to be human—both in seeking to understand the world and in trying to make sense of our own existence.

---

8. Meaning and Culture

Culture profoundly influences meaning, shaping both the creation and interpretation of signs, symbols, and experiences. Meaning is rarely absolute—it is context-dependent, and much of that context is cultural.

- Shared Symbols and Language: Culture provides a common set of symbols, metaphors, idioms, and language structures. For example, the meaning of a gesture, color, or word may be positive in one culture and negative in another (e.g., the color white symbolizes purity in Western cultures but mourning in some East Asian traditions).

- Socialization: Through family, traditions, rituals, education, and media, individuals learn cultural meanings, which guide how they understand themselves, others, and the world.

- Collective Narratives & Worldviews: Cultures transmit meaning through myths, stories, religious beliefs, and collective memories, shaping peoples' sense of purpose and significance.

- Interpretative Communities: Stanley Fish and others argue that what is meaningful is determined by “interpretive communities”—groups that share similar ways of making sense of the world. Thus, meaning is not just found in the individual or the text, but in the shared cultural practices of a community.

- Dynamic & Negotiated: Cultural meanings change and are continuously renegotiated through contact with other cultures, generational shifts, and historical events.

In summary, culture functions as both a lens and a framework that gives structure to meaning, making it possible for individuals to communicate, belong, and find purpose. No act of meaning-making is entirely isolated from cultural influence; even the most personal interpretations are filtered through, and often shaped by, the cultural narratives that surround us.

---

Updated Summary Table

| Discipline      | Core Idea of Meaning                                    |
|-----------------|--------------------------------------------------------|
| Linguistics     | Relation between signs/symbols and what they represent |
| Philosophy      | Sense, reference, utility, existence                   |
| Psychology      | Interpretation, coherence, personal significance       |
| Mysticism       | Hidden, experiential, transcendent                     |
| Computer Science| Syntax vs. semantics vs. pragmatics                    |
| Cultural Studies| Negotiated, contextual, dynamic, shared                |

Thus, culture is not just an influence on meaning—it is often the very soil from which shared meanings emerge.
""".strip()

        if user_id in self.profiles:
            profile = self.profiles[user_id]
            concept.relative_meaning = profile.semantic_shifts.get(target_word.lower(), 0.0) * 0.5
            concept.relative_associations = {k: min(0.1, v) for k, v in profile.semantic_shifts.items()}
            concept.relative_nuance = np.array([
                profile.semantic_shifts.get('positive', 0) * 0.2,
                profile.semantic_shifts.get('negative', 0) * 0.2,
                profile.semantic_shifts.get('complex', 0) * 0.2
            ])
            concept.relative_context = profile.relative_context[-5:]
            contextual_weight = len([c for c in concept.relative_context if target_word.lower() in c.lower()]) / max(1, len(concept.relative_context))
            concept.relative_meaning += contextual_weight * 0.1
            concept.relative_meaning = min(1.0, concept.relative_meaning)

# ... (rest of the code remains the same)

"""Please add everything from the above code to test.py which would optimize its reasoning and ability to identify and make decisions and provide accurate answers based upon everything the program produces leveraging all already built into MacBook m1's dictionaries and word meaning, definition, nuance databases. Add as many helpers as needed. Layers for specific to malware detection and a layer specific to general decision making based upon the provided information with a strong sense of logic and reason, situational awareness and intuitive judgement based upon the information provided etc."""

"""Enjoy"""


@dataclass
class ExposureProfile:
    """Represents a user's exposure and semantic profile."""
    user_id: str
    semantic_shifts: Dict[str, float] = field(default_factory=lambda: defaultdict(float))
    nuance_keywords: List[str] = field(default_factory=list)
    total_exposure_count: int = 0
    relative_context: List[str] = field(default_factory=list)
    
    def from_text(self, text: str):
        """Processes text to update the profile."""
        import re
        words = re.findall(r'\b\w+\b', text.lower())
        for word in set(words):
            self.semantic_shifts[word] += 0.01
        self.total_exposure_count += 1
        
        sentences = re.split(r'[.!?]+', text)
        self.relative_context.extend([s.strip() for s in sentences if len(s.strip()) > 10])
        
        if 'it' in text.lower():
            for sent in self.relative_context:
                if 'meaning' in sent.lower() or 'context' in sent.lower():
                    self.semantic_shifts['it'] = min(0.5, self.semantic_shifts.get('it', 0) + 0.05)


@dataclass
class ConceptState:
    id: str
    cognitive_level: CognitiveLevel
    description: str = ""
    
    universal_def: str = field(default="")
    relative_meaning: float = field(default=0.0)
    relative_associations: Dict[str, float] = field(default_factory=dict)
    relative_nuance: np.ndarray = field(default_factory=lambda: np.zeros(3))
    relative_context: List[str] = field(default_factory=list)
    
    creation_time: float = field(default_factory=time.time)
    last_update: float = field(default_factory=time.time)
    layer: str = "l1"
    user_id: Optional[str] = None
    target_word: Optional[str] = None


@staticmethod
def compute_all_metrics(state: np.ndarray, previous: np.ndarray, cognitive_level: CognitiveLevel,
                       ethical_bias: float = 0.0, rel_meaning: float = 0.0, rel_nuance: np.ndarray = np.zeros(3),
                       rel_context_len: int = 0) -> Dict[str, float]:
    """Compute all T-AIC metrics with personalization parameters."""
    try:
        config = TAICConfig()
        
        state_change = np.linalg.norm(state - previous_padded)
        srm = np.exp(-state_change) * (1 + rel_context_len * 0.02)
        
        complexity = np.log10(cognitive_level.parameter_count + 1)
        map_val = srm / complexity if complexity > 0 else srm
        cbmi = srm * 0.7 + (1.0 - normalized_entropy) * 0.3
        
        bcp_base = cbmi * map_val
        bcp = min(1.0, bcp_base + ethical_bias * 0.2 + rel_meaning * 0.1)
        bcp *= (1 + (rel_context_len / 10.0))
        bcp = min(1.0, bcp)
        
        trajectory = 1.0 - normalized_entropy + np.sum(rel_nuance) * 0.05
        trajectory = min(1.0, trajectory)
        
        gab = 0.0
        if normalized_entropy < 0.2 and srm > 0.8:
            gab = min(1.0, (0.8 - normalized_entropy) * srm)
        
        convergence_score = (
            (1 - normalized_entropy) * config.weight_entropy +
            trajectory * config.weight_trajectory +
            srm * config.weight_srm +
            bcp * config.weight_bcp +
            gab * config.weight_gab
        )
        
        return {
            'entropy': float(normalized_entropy),
            'srm': float(srm),
            'map': float(map_val),
            'cbmi': float(cbmi),
            'bcp': float(bcp),
            'trajectory': float(trajectory),
            'gab': float(gab),
            'convergence_score': float(convergence_score),
            'relative_context_len': rel_context_len,
            'contextual_weight': float(rel_context_len / 10.0)
        }
    except Exception as e:
        pass


class PersonalizationEngine:
    """Manages user-specific concept adaptation."""
    
    def __init__(self):
        self.profiles: Dict[str, ExposureProfile] = {}
    
    def create_or_update_profile(self, user_id: str, exposure_text: str):
        profile = self.profiles.get(user_id, ExposureProfile(user_id=user_id))
        profile.from_text(exposure_text)
        self.profiles[user_id] = profile
        return profile
    
    def adapt_concept_for_user(self, concept: ConceptState, user_id: str, target_word: str = "compassion"):
        """Adapt concept state using user profile data."""
        if target_word == "it":
            concept.universal_def = "The subjective and objective case of the third person singular neuter pronoun in English. Referential: to things/ideas; Impersonal: weather/time; Emphatic: identity/focus."
        elif target_word == "compassion":
            concept.universal_def = "Sympathetic pity and concern for the sufferings or misfortunes of others."
        
        if user_id in self.profiles:
            profile = self.profiles[user_id]
            concept.relative_meaning = profile.semantic_shifts.get(target_word.lower(), 0.0) * 0.5
            concept.relative_associations = {k: min(0.1, v) for k, v in profile.semantic_shifts.items()}
            concept.relative_nuance = np.array([
                profile.semantic_shifts.get('positive', 0) * 0.2,
                profile.semantic_shifts.get('negative', 0) * 0.2,
                profile.semantic_shifts.get('complex', 0) * 0.2
            ])
            concept.relative_context = profile.relative_context[-5:]
            
            contextual_weight = len([c for c in concept.relative_context if target_word.lower() in c.lower()]) / max(1, len(concept.relative_context))
            concept.relative_meaning += contextual_weight * 0.1
            concept.relative_meaning = min(1.0, concept.relative_meaning)


# In OptimizedTAIC.__init__
self.personalization = PersonalizationEngine()


def create_concept(self, description: str,
                  cognitive_level: CognitiveLevel = CognitiveLevel.META_COGNITION,
                  layer: str = 'l1',
                  ethical_bias: float = 0.0,
                  user_id: Optional[str] = None,
                  target_word: Optional[str] = None) -> str:
    """Create new concept with personalization support."""
    concept_id = f"{layer}_{int(time.time() * 1000000) % 1000000:06x}"
    concept = ConceptState(
        id=concept_id,
        cognitive_level=cognitive_level,
        description=description,
        ethical_bias=ethical_bias,
        layer=layer,
        user_id=user_id,
        target_word=target_word
    )
    
    if user_id and target_word:
        self.personalization.adapt_concept_for_user(concept, user_id, target_word)


# In CausalEngine.process_step
rel_meanings = np.array([c.relative_meaning for c in concepts])
rel_nuances = np.array([np.sum(c.relative_nuance) for c in concepts])
rel_context_lens = np.array([len(c.relative_context) for c in concepts])

use_gpu = self.config.enable_gpu and TORCH_AVAILABLE
metrics = MetricEngine.batch_compute(
    concepts,
    use_gpu=use_gpu,
    rel_meanings=rel_meanings,
    rel_nuances=rel_nuances,
    rel_context_lens=rel_context_lens
)


@staticmethod
def batch_compute(states: List[ConceptState],
                 use_gpu: bool = True,
                 rel_meanings: Optional[np.ndarray] = None,
                 rel_nuances: Optional[np.ndarray] = None,
                 rel_context_lens: Optional[np.ndarray] = None) -> Dict[str, np.ndarray]:
    if rel_context_lens is not None:
        context_lens_tensor = torch.tensor(rel_context_lens, device=device, dtype=torch.float32)
        srm_tensor = srm_tensor * (1 + context_lens_tensor * 0.02)
        bcp_tensor = bcp_tensor * (1 + context_lens_tensor / 10.0)
        bcp_tensor = torch.clamp(bcp_tensor, max=1.0)

"""
This module integrates advanced conceptual profiling and personalized semantic adaptation.

---
NUANCE REFERENCE
----------------
Certainly! Here is a comprehensive and detailed exploration of “nuance”—integrating linguistic, philosophical,
psychological, artistic, and mystical perspectives at university level.

## 1. Linguistic & Lexical Perspectives

### a. Definition:
- Nuance (noun): A subtle distinction or variation in meaning, expression, sound, feeling, tone, or response.

### b. Etymology:
- From French “nuance,” from Old French “nuer” (to shade), derived from Latin “nubes” (cloud), originally referencing subtle differences in color or shade.

### c. Nuance in Language:
- Subtle shifts in word choice, syntax, tone, or context can introduce nuances that alter meaning.
- Example: The sentences "He’s angry" and "He’s a bit displeased" carry nuanced differences in intensity and implication.

## 2. Philosophical Perspectives

### a. Epistemology (Theories of Knowledge):
- Nuance acknowledges the complexity of knowledge and resists reductionism.
- It recognizes the “gray areas”—the subtle gradations between binaries and the inadequacy of black-and-white thinking.

### b. Hermeneutics (Interpretation):
- Nuance is central to interpretation, demanding sensitivity to context, voice, intention, and subtext.
- Gadamer and Ricoeur stress that true understanding involves attending to nuances embedded in language and culture.

### c. Ethics and Morality:
- Many ethical dilemmas require attention to nuances: the specific context, intentions, relationships, and consequences.

## 3. Psychological & Cognitive Science Perspectives

### a. Perception and Cognition:
- Humans are wired to detect and interpret nuances—fine details in facial expressions, intonation, or behavior.
- Expert knowledge increases sensitivity to nuance (e.g., a wine expert detecting subtle flavors).

### b. Emotional Intelligence:
- Recognizing emotional nuances in oneself and others is key to empathy and effective communication.

## 4. Nuance in Art and Aesthetics

### a. Visual and Performing Arts:
- Painting: Nuance may refer to subtle gradations of color, light, or shadow (chiaroscuro).
- Music: Subtle variations in dynamics, tempo, or interpretation create emotional richness.
- Literature: Nuance appears in subtext, irony, understatement, double meanings, or ambiguity.
- Dance/Drama: Nuanced performance conveys complex emotions through minute bodily or vocal inflections.

### b. Art Criticism:
- Sophisticated criticism and appreciation depend on perceiving and savoring nuance.

## 5. Social and Cultural Perspectives

### a. Cultural Sensitivity:
- Social interactions are governed by nuanced codes (e.g., politeness, humor, innuendo), which vary across cultures.
- Sensitivity to cultural nuance avoids misunderstanding and fosters global competence.

### b. Political Discourse:
- Nuanced argumentation resists polarization and dogmatism, allowing for complexity and compromise.

## 6. Mystical & Spiritual Perspectives

### a. Mysticism:
- Many mystical traditions focus on the ineffable—experiences that transcend conceptual clarity and are understood through subtle intuition or direct insight.
- “Nuance” here might refer to the fine gradations of spiritual feeling or insight not easily put into words.

### b. Symbolism:
- Esoteric traditions (e.g., Kabbalah, Sufism) cherish nuanced interpretations of sacred texts—hidden meanings perceived only through subtle, contemplative reading.

## 7. Interdisciplinary Insights

### a. Science & Mathematics:
- Scientific theories often depend on nuanced distinctions (e.g., between correlation and causation, or different types of probability).

### b. Law:
- Legal reasoning and the practice of justice rest on nuance—a careful distinction of cases, precedents, and circumstances.

## 8. The Value and Challenge of Nuance

- Complexity: Nuance brings depth and richness but often complicates decision-making and communication.
- Vulnerability to Oversimplification: Modern discourse, especially in media and politics, often eschews nuance for clarity or persuasion, risking misunderstanding or inaccuracy.
- Essential for Sophistication: Intellectual, artistic, and moral sophistication hinge on a nuanced appreciation of reality.

## 9. Culture and Nuance

Culture shapes what is considered “nuanced.” What seems subtle in one culture may be blatant in another, and vice versa. Sensitivity to nuance in cross-cultural communication prevents misinterpretation and deepens understanding.

## 10. Summary Table

| Discipline         | Nuance Refers To                                   |
|--------------------|---------------------------------------------------|
| Linguistics        | Subtle distinction in word, meaning, or tone      |
| Philosophy         | Complexity, ambiguity, resisting reductionism      |
| Psychology         | Fine perception of emotion, behavior, thought      |
| Art & Literature   | Subtlety in technique, form, interpretation        |
| Mysticism          | Ineffable gradations of meaning, spiritual insight |
| Culture            | Social codes, context, etiquette, humor, etc.      |

## Key Quotes and Aphorisms

- “Truth is rarely pure and never simple.” — Oscar Wilde (on the value of nuance)
- “It is the mark of an educated mind to be able to entertain a thought without accepting it.” — Aristotle (on embracing complexity)
- “In the depth of winter, I finally learned that within me there lay an invincible summer.” — Albert Camus (on nuance of feeling)

## Synthesis

In essence, “nuance” refers to the subtle variations, gradations, and complexities that enrich all forms of meaning, perception, and expression. It is the recognition of what lies between the obvious and the oppositional: the shades, undertones, and ambiguous spaces that constitute the fullness of experience, thought, and communication. Embracing nuance is essential for deep understanding, interpretation, empathy, and creativity—whether in philosophy, art, language, or life itself.
---
"""

NUANCE_KNOWLEDGE = {
    "short_definition": "Nuance is a subtle distinction or variation in meaning, tone, expression, feeling, or context.",
    "linguistic": "In language, nuance refers to the fine gradations that alter meaning, often marked by word choice, tone, or syntax.",
    "philosophical": "Nuance resists reductionism and acknowledges complexity, ambiguity, context, and the grey areas of thought.",
    "psychology": "Humans perceive and process subtle details—nuances—in emotion, expression, perception, and understanding.",
    "art": "In art, music, literature, and performance, nuance is found in technique, subtext, irony, and emotional inflection.",
    "cultural": "Social codes, etiquette, and humor are nuanced and culture-dependent; sensitivity to nuance is key for cross-cultural fluency.",
    "mystical": "Nuance in mysticism involves the ineffable, subtle gradations of insight and spiritual meaning.",
    "summary_table": [
        ("Linguistics", "Subtle distinction in word, meaning, or tone"),
        ("Philosophy", "Complexity, ambiguity, resisting reductionism"),
        ("Psychology", "Fine perception of emotion, behavior, thought"),
        ("Art & Literature", "Subtlety in technique, form, interpretation"),
        ("Mysticism", "Ineffable gradations of meaning, spiritual insight"),
        ("Culture", "Social codes, context, etiquette, humor, etc."),
    ],
    "quotes": [
        "Truth is rarely pure and never simple. — Oscar Wilde",
        "It is the mark of an educated mind to be able to entertain a thought without accepting it. — Aristotle",
        "In the depth of winter, I finally learned that within me there lay an invincible summer. — Albert Camus",
    ],
    "synthesis": (
        "Nuance refers to the subtle variation and complexity underlying all perception, communication, "
        "and experience. Recognizing nuance is essential for sophistication, empathy, and wise decision-making."
    )
}

def get_nuance_overview(as_summary: bool = False) -> str:
    """Return an integrated, interdisciplinary overview of 'Nuance'."""
    if as_summary:
        return NUANCE_KNOWLEDGE['synthesis']
    else:
        return __doc__.split('NUANCE REFERENCE')[1].strip().lstrip('-').strip() if 'NUANCE REFERENCE' in __doc__ else 'See NUANCE_KNOWLEDGE.'

# ... Remainder of original code (dataclasses, logic, etc.)

class ConceptState:
    # ... existing ConceptState fields and methods

    def enrich_with_nuance(self):
        """Attach a full interdisciplinary exposition of 'Nuance' to this concept."""
        self.nuance_academic_overview = get_nuance_overview(as_summary=False)
        self.nuance_short = NUANCE_KNOWLEDGE["short_definition"]

# You can now provide context-aware, academically complete answers to "what is nuance"
# by calling get_nuance_overview() or referencing ConceptState().enrich_with_nuance() results.



from dataclasses import dataclass, field
from typing import Dict, List, Optional, Callable
from collections import defaultdict
import time
import numpy as np
import subprocess
import platform
import os
import re
import json

try:
    import torch
    TORCH_AVAILABLE = True
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
except ImportError:
    TORCH_AVAILABLE = False
    device = None

# --- DOMAIN SUPPORT CLASSES & CONSTANTS ---

class TAICConfig:
    weight_entropy = 0.2
    weight_trajectory = 0.2
    weight_srm = 0.2
    weight_bcp = 0.2
    weight_gab = 0.2

class CognitiveLevel:
    META_COGNITION = 2
    parameter_count = 1000

NUANCE_KNOWLEDGE = {
    "short_definition": "Nuance is a subtle distinction or variation in meaning, tone, expression, feeling, or context.",
    "linguistic": "In language, nuance refers to the fine gradations that alter meaning, often marked by word choice, tone, or syntax.",
    "philosophical": "Nuance resists reductionism and acknowledges complexity, ambiguity, context, and the grey areas of thought.",
    "psychology": "Humans perceive and process subtle details—nuances—in emotion, expression, perception, and understanding.",
    "art": "In art, music, literature, and performance, nuance is found in technique, subtext, irony, and emotional inflection.",
    "cultural": "Social codes, etiquette, and humor are nuanced and culture-dependent; sensitivity to nuance is key for cross-cultural fluency.",
    "mystical": "Nuance in mysticism involves the ineffable, subtle gradations of insight and spiritual meaning.",
    "summary_table": [
        ("Linguistics", "Subtle distinction in word, meaning, or tone"),
        ("Philosophy", "Complexity, ambiguity, resisting reductionism"),
        ("Psychology", "Fine perception of emotion, behavior, thought"),
        ("Art & Literature", "Subtlety in technique, form, interpretation"),
        ("Mysticism", "Ineffable gradations of meaning, spiritual insight"),
        ("Culture", "Social codes, context, etiquette, humor, etc."),
    ],
    "quotes": [
        "Truth is rarely pure and never simple. — Oscar Wilde",
        "It is the mark of an educated mind to be able to entertain a thought without accepting it. — Aristotle",
        "In the depth of winter, I finally learned that within me there lay an invincible summer. — Albert Camus",
    ],
    "synthesis": (
        "Nuance refers to the subtle variation and complexity underlying all perception, communication, "
        "and experience. Recognizing nuance is essential for sophistication, empathy, and wise decision-making."
    )
}

def get_nuance_overview(as_summary: bool = False) -> str:
    if as_summary:
        return NUANCE_KNOWLEDGE['synthesis']
    else:
        return (
            "Certainly! Here is a comprehensive and detailed exploration of “nuance”—integrating linguistic, philosophical, "
            "psychological, artistic, and mystical perspectives at university level.\n"
            "---\n(See code docstring for full multi-page academic exposition, or see NUANCE_KNOWLEDGE above for summary forms.)"
        )

def is_macos() -> bool:
    return platform.system() == "Darwin"

def system_dictionary_lookup(word: str) -> str:
    if not is_macos():
        return ""
    # AppleScript to Dictionary.app for definition (may be slow)
    script = f'''
    set theDefinition to ""
    try
        tell application "Dictionary"
            set theDefinition to (definition for "{word}")
        end tell
    end try
    return theDefinition
    '''
    try:
        output = subprocess.check_output(['osascript', '-e', script])
        definition = output.decode("utf-8").strip()
        if definition:
            return definition
    except Exception:
        pass

    # Fallback using dict command (if installed)
    try:
        output = subprocess.check_output(['dict', word])
        return output.decode('utf-8')
    except Exception:
        pass

    return ""

def get_builtin_mac_dictionaries() -> List[str]:
    if not is_macos():
        return []
    dicts_path = "/Library/Dictionaries/"
    try:
        dicts = os.listdir(dicts_path)
        return [d for d in dicts if d.endswith('.dictionary')]
    except Exception:
        return []

def first_definition(word: str) -> str:
    text = system_dictionary_lookup(word)
    if text:
        m = re.search(r"\n([a-z].+?)[\n\r]", text, re.IGNORECASE)
        if m:
            return m.group(1).strip()
        return text.strip().split('\n')[0]
    else:
        return NUANCE_KNOWLEDGE.get("short_definition" if word.lower()=="nuance" else "synthesis", "No definition found.")

def word_synonyms(word: str) -> List[str]:
    if not is_macos():
        return []
    script = f'''
    set theSynonyms to ""
    try
        tell application "Dictionary"
            set theSynonyms to synonyms for "{word}"
        end tell
    end try
    return theSynonyms
    '''
    try:
        output = subprocess.check_output(['osascript', '-e', script])
        term = output.decode("utf-8").strip()
        if term:
            return [t.strip() for t in term.split(',') if t.strip()]
    except Exception:
        pass
    return []

# ------- PROFILE DATA CLASSES AND SEMANTIC STATE -----------

@dataclass
class ExposureProfile:
    user_id: str
    semantic_shifts: Dict[str, float] = field(default_factory=lambda: defaultdict(float))
    nuance_keywords: List[str] = field(default_factory=list)
    total_exposure_count: int = 0
    relative_context: List[str] = field(default_factory=list)
    
    def from_text(self, text: str):
        words = re.findall(r'\b\w+\b', text.lower())
        for word in set(words):
            self.semantic_shifts[word] += 0.01
        self.total_exposure_count += 1
        sentences = re.split(r'[.!?]+', text)
        self.relative_context.extend([s.strip() for s in sentences if len(s.strip()) > 10])
        if 'it' in text.lower():
            for sent in self.relative_context:
                if 'meaning' in sent.lower() or 'context' in sent.lower():
                    self.semantic_shifts['it'] = min(0.5, self.semantic_shifts.get('it', 0) + 0.05)

@dataclass
class ConceptState:
    id: str
    cognitive_level: CognitiveLevel
    description: str = ""
    universal_def: str = field(default="")
    relative_meaning: float = field(default=0.0)
    relative_associations: Dict[str, float] = field(default_factory=dict)
    relative_nuance: np.ndarray = field(default_factory=lambda: np.zeros(3))
    relative_context: List[str] = field(default_factory=list)
    creation_time: float = field(default_factory=time.time)
    last_update: float = field(default_factory=time.time)
    layer: str = "l1"
    user_id: Optional[str] = None
    target_word: Optional[str] = None
    ethical_bias: float = 0.0

    nuance_academic_overview: str = ""
    nuance_short: str = ""

    def __repr__(self):
        return (f"ConceptState(id={self.id}, universal_def={self.universal_def[:30]}..., "
                f"relative_meaning={self.relative_meaning:.3f}, layer={self.layer}, user_id={self.user_id}, target_word={self.target_word})")

    def enrich_with_nuance(self):
        self.nuance_academic_overview = get_nuance_overview(as_summary=False)
        self.nuance_short = NUANCE_KNOWLEDGE["short_definition"]

    def enrich_with_mac_dictionary(self):
        if self.target_word:
            defn = first_definition(self.target_word)
            self.universal_def = defn
            syns = word_synonyms(self.target_word)
            if syns:
                self.relative_associations['synonyms'] = syns

# ---------------------- Metric Computation ----------------------------

def compute_all_metrics(state: np.ndarray, previous: np.ndarray, cognitive_level: CognitiveLevel,
                        ethical_bias: float = 0.0, rel_meaning: float = 0.0, rel_nuance: np.ndarray = np.zeros(3),
                        rel_context_len: int = 0) -> Dict[str, float]:
    try:
        config = TAICConfig()
        size = max(state.shape[0], previous.shape[0])
        state_padded = np.zeros(size)
        previous_padded = np.zeros(size)
        state_padded[:state.shape[0]] = state
        previous_padded[:previous.shape[0]] = previous
        state_change = np.linalg.norm(state_padded - previous_padded)
        normalized_entropy = np.clip(np.sum(np.abs(state_padded - previous_padded))/size, 0.0, 1.0)
        srm = np.exp(-state_change) * (1 + rel_context_len * 0.02)
        complexity = np.log10(getattr(cognitive_level, "parameter_count", 1000) + 1)
        map_val = srm / complexity if complexity > 0 else srm
        cbmi = srm * 0.7 + (1.0 - normalized_entropy) * 0.3
        bcp_base = cbmi * map_val
        bcp = min(1.0, bcp_base + ethical_bias * 0.2 + rel_meaning * 0.1)
        bcp *= (1 + (rel_context_len / 10.0))
        bcp = min(1.0, bcp)
        trajectory = 1.0 - normalized_entropy + np.sum(rel_nuance) * 0.05
        trajectory = min(1.0, trajectory)
        gab = 0.0
        if normalized_entropy < 0.2 and srm > 0.8:
            gab = min(1.0, (0.8 - normalized_entropy) * srm)
        convergence_score = (
            (1 - normalized_entropy) * config.weight_entropy +
            trajectory * config.weight_trajectory +
            srm * config.weight_srm +
            bcp * config.weight_bcp +
            gab * config.weight_gab
        )
        return {
            'entropy': float(normalized_entropy),
            'srm': float(srm),
            'map': float(map_val),
            'cbmi': float(cbmi),
            'bcp': float(bcp),
            'trajectory': float(trajectory),
            'gab': float(gab),
            'convergence_score': float(convergence_score),
            'relative_context_len': rel_context_len,
            'contextual_weight': float(rel_context_len / 10.0)
        }
    except Exception as e:
        return {}

# ----------------- Personalization Engine --------------------------

class PersonalizationEngine:
    def __init__(self):
        self.profiles: Dict[str, ExposureProfile] = {}
        self.profile_save_path = "profile_store.json"

    def create_or_update_profile(self, user_id: str, exposure_text: str):
        profile = self.profiles.get(user_id, ExposureProfile(user_id=user_id))
        profile.from_text(exposure_text)
        self.profiles[user_id] = profile
        return profile

    def adapt_concept_for_user(self, concept: ConceptState, user_id: str, target_word: str = "compassion"):
        # macOS and static built-in dictionary definitions
        if target_word:
            concept.enrich_with_mac_dictionary()
        # Add academic/nuance if word suggestive:
        if target_word and target_word.lower() == "nuance":
            concept.enrich_with_nuance()
        if user_id in self.profiles:
            profile = self.profiles[user_id]
            concept.relative_meaning = profile.semantic_shifts.get(target_word.lower(), 0.0) * 0.5
            concept.relative_associations.update({k: min(0.1, v) for k, v in profile.semantic_shifts.items()})
            concept.relative_nuance = np.array([
                profile.semantic_shifts.get('positive', 0) * 0.2,
                profile.semantic_shifts.get('negative', 0) * 0.2,
                profile.semantic_shifts.get('complex', 0) * 0.2
            ])
            concept.relative_context = profile.relative_context[-5:]
            contextual_weight = len([c for c in concept.relative_context if target_word.lower() in c.lower()]) / max(1, len(concept.relative_context))
            concept.relative_meaning += contextual_weight * 0.1
            concept.relative_meaning = min(1.0, concept.relative_meaning)

    def save_profiles(self):
        with open(self.profile_save_path, "w") as f:
            data = {uid: dict(
                        semantic_shifts=dict(p.semantic_shifts),
                        nuance_keywords=list(p.nuance_keywords),
                        total_exposure_count=p.total_exposure_count,
                        relative_context=list(p.relative_context))
                for uid, p in self.profiles.items()}
            json.dump(data, f)

    def load_profiles(self):
        try:
            with open(self.profile_save_path) as f:
                data = json.load(f)
                self.profiles = {
                    uid: ExposureProfile(
                        user_id=uid,
                        semantic_shifts=defaultdict(float, v["semantic_shifts"]),
                        nuance_keywords=v["nuance_keywords"],
                        total_exposure_count=v["total_exposure_count"],
                        relative_context=v["relative_context"]
                    )
                    for uid, v in data.items()
                }
        except Exception:
            self.profiles = {}

# ------- TAIC (Core) and Layers for Reasoning --------------

class OptimizedTAIC:
    def __init__(self):
        self.personalization = PersonalizationEngine()

    def create_concept(self, description: str,
                       cognitive_level: CognitiveLevel = CognitiveLevel.META_COGNITION,
                       layer: str = 'l1',
                       ethical_bias: float = 0.0,
                       user_id: Optional[str] = None,
                       target_word: Optional[str] = None) -> ConceptState:
        """Create new concept with personalization and dictionary/nuance support."""
        concept_id = f"{layer}_{int(time.time() * 1000000) % 1000000:06x}"
        concept = ConceptState(
            id=concept_id,
            cognitive_level=cognitive_level,
            description=description,
            ethical_bias=ethical_bias,
            layer=layer,
            user_id=user_id,
            target_word=target_word
        )
        if user_id and target_word:
            self.personalization.adapt_concept_for_user(concept, user_id, target_word)
        return concept

# ----- General Reasoning & Decision Layer with Informed, Situational, and Intuitive Judgement -------

class DecisionLayer:
    """General decision-making layer utilizing context, task-awareness, and intuitive judgement."""

    def informed_decision(self, context: List[str], task: str, options: List[str]) -> str:
        """
        Makes an informed decision based on context, task, and available options.
        """
        context_str = " ".join(context).lower()
        matches = []
        for option in options:
            if option.lower() in context_str or option.lower() in task.lower():
                matches.append(option)
        if matches:
            return f"Informed choice based on context/task: {matches[0]}"
        # Simulate "reasonable" intuition using semantic features
        import random
        fallback_choice = random.choice(options)
        return f"Intuitive judgement: {fallback_choice} (no explicit context match)"

    def situational_awareness(self, context: List[str], task: str) -> str:
        """
        Assess situation and returns a brief awareness statement.
        """
        awareness_points = []
        keywords = ['delay', 'priority', 'completed', 'uncertain', 'critical', 'risk', 'required', 'optional']
        for kw in keywords:
            for sent in context:
                if kw in sent.lower():
                    awareness_points.append(f"{kw} detected in context.")
        if "urgent" in task.lower():
            awareness_points.append("Task marked as urgent.")
        if not awareness_points:
            return "Situation normal. No immediate signals detected."
        return "Situational awareness: " + "; ".join(awareness_points)

    def intuitive_judgement(self, context: List[str], task: str) -> str:
        # Extremely simple prototype using position and emotion
        pos_words = ['good', 'efficient', 'positive', 'quick', 'trusted']
        neg_words = ['bad', 'slow', 'negative', 'uncertain', 'problematic']
        summary = []
        for s in context:
            if any(w in s.lower() for w in pos_words):
                summary.append("Favorable context detected.")
            if any(w in s.lower() for w in neg_words):
                summary.append("Unfavorable context detected.")
        if any(w in task.lower() for w in pos_words):
            summary.append("Task framing is positive.")
        elif any(w in task.lower() for w in neg_words):
            summary.append("Task framing is negative.")
        if not summary:
            summary.append("No strong intuitive signal found.")
        return " ".join(summary)

# ------- Command-line/Main Entrypoint including macOS dictionary usage --------

def interactive_demo():
    print("OptimizedTAIC (Mac Dictionary Edition) - Informed Decision Making Demo")
    taic = OptimizedTAIC()
    personalization = taic.personalization
    decision = DecisionLayer()
    personalization.load_profiles()
    user = "alice"

    while True:
        try:
            word = input("\nEnter a word/concept (or 'quit'): ").strip()
            if word.lower() == "quit":
                break
            definition = first_definition(word)
            print(f"[Mac Dictionary] Definition of '{word}':\n{definition}\n")
            synonyms = word_synonyms(word)
            if synonyms:
                print(f"[Mac Dictionary] Synonyms: {', '.join(synonyms)}")
            # Simulate exposure/profile update
            personalization.create_or_update_profile(user, f"{word}: {definition}")
            # Create and process concept
            concept = taic.create_concept(
                description=f"Profiled concept: {word}",
                user_id=user,
                target_word=word
            )
            print("[TAIC] Universal def:", concept.universal_def)
            print("[TAIC] Relative meaning:", concept.relative_meaning)
            print("[TAIC] Relative nuance vector:", concept.relative_nuance)
            print("[TAIC] Profiled context (last 3):", concept.relative_context[-3:])

            # Informed decision making
            context_input = input("\nEnter context sentence(s): ").strip()
            context = [context_input]
            task = input("Enter current task/goal description: ").strip()
            options = input("Enter possible decision options (comma-separated): ").strip().split(",")
            options = [o.strip() for o in options if o.strip()]
            decision_result = decision.informed_decision(context, task, options)
            print("[DecisionLayer] Informed decision:", decision_result)
            awareness = decision.situational_awareness(context, task)
            print("[DecisionLayer] Situational awareness:", awareness)
            judgement = decision.intuitive_judgement(context, task)
            print("[DecisionLayer] Intuitive judgement:", judgement)
        except KeyboardInterrupt:
            print("\nExiting.")
            break
        except Exception as e:
            print("Error:", e)
            continue
    personalization.save_profiles()
    print("Profiles saved. Bye.")

if __name__ == "__main__":
    if is_macos():
        interactive_demo()
    else:
        print("This demo is designed for macOS with built-in Dictionary.app functionality.")
        
from typing import List, Dict, Any

class Meme:
    """
    Represents a meme: a transmissible unit of cultural information (idea, skill, behavior).
    Mimics gene-like evolutionary propagation in language, thought, and behavior.
    """
    def __init__(self, content: str, meme_type: str, origin: str = "", context_tags: List[str] = None):
        self.content = content  # e.g. phrase, behavior, idea
        self.meme_type = meme_type  # e.g. 'language', 'skill', 'norm'
        self.origin = origin  # e.g. 'Dawkins', 'Internet', etc.
        self.context_tags = context_tags or []
        self.generation = 0  # How many replication steps

    def mutate(self, mutation: str) -> "Meme":
        """Return a mutated/variant meme (e.g., new slang edge-case, evolved protocol)."""
        new_content = f"{self.content} {mutation}"
        return Meme(new_content, self.meme_type, self.origin, self.context_tags + ["mutated"])


class Memeplex:
    """
    Represents a collection of memes (a meme ecosystem, e.g., a language, subculture, ideology).
    Handles their propagation, mutation, and influence.
    """
    def __init__(self, memes: List[Meme] = None):
        self.memes: List[Meme] = memes or []

    def propagate(self, receiver: "Agent"):
        """Transmits memes to an agent, influencing their speech, thought, or behavior."""
        for meme in self.memes:
            receiver.install_meme(meme)

    def mutate_all(self):
        """Randomly mutate all memes in the memeplex (simulates cultural evolution)."""
        import random
        for meme in self.memes:
            if random.random() < 0.1:  # 10% mutation rate
                mutated = meme.mutate("evolved")
                self.memes.append(mutated)

    def filter_by_type(self, meme_type: str) -> List[Meme]:
        return [m for m in self.memes if m.meme_type == meme_type]


class Agent:
    """
    Represents a human/system agent with linguistic, cognitive, and behavioral layers.
    Memes act as 'mental software modules' downloaded/installed to these layers.
    """
    def __init__(self):
        self.language_modules: List[Meme] = []
        self.cognitive_frameworks: List[Meme] = []
        self.behavioral_protocols: List[Meme] = []
        self.meme_history: List[str] = []  # Record all meme installs

    def install_meme(self, meme: Meme):
        """Install a meme into the appropriate layer."""
        if meme.meme_type == "language":
            self.language_modules.append(meme)
        elif meme.meme_type == "cognitive":
            self.cognitive_frameworks.append(meme)
        elif meme.meme_type == "behavior":
            self.behavioral_protocols.append(meme)
        self.meme_history.append(meme.content)

    def speak(self) -> List[str]:
        """Produce utterances influenced by installed memes."""
        return [meme.content for meme in self.language_modules]

    def think(self) -> List[str]:
        """Produce 'thought patterns' from cognitive memes."""
        return [meme.content for meme in self.cognitive_frameworks]

    def act(self) -> List[str]:
        """Output behavior patterns based on installed memes."""
        return [meme.content for meme in self.behavioral_protocols]

    def summary(self) -> Dict[str, Any]:
        return {
            "language_memes": [m.content for m in self.language_modules],
            "cognitive_memes": [m.content for m in self.cognitive_frameworks],
            "behavior_memes": [m.content for m in self.behavioral_protocols],
        }


class MemeSimulator:
    """
    Simulates the propagation of meme modules (as cognitive software units) throughout a population.
    """
    def __init__(self, agents: List[Agent], memeplex: Memeplex):
        self.agents = agents
        self.memeplex = memeplex

    def run_generation(self):
        """Propagate memes to all agents and advance meme evolution."""
        for agent in self.agents:
            self.memeplex.propagate(agent)
        self.memeplex.mutate_all()

    def show_population_state(self):
        """Summarize the state of all agents."""
        return [agent.summary() for agent in self.agents]
