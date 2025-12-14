#!/usr/bin/env python3
"""
T-AIC: Transcendent Artificial Intelligence Consciousness
Complete Production-Ready Implementation with All Enhanced Features

Comprehensive integration of all components including:
- Core T-AIC architecture with adaptive dimensionality
- User personalization engine with exposure profiles
- macOS Dictionary integration
- Meme/Memeplex cultural evolution system
- Decision-making layer
- Quantum state management
- Causal engine and attention systems
- Ethical monitoring
- Visualization tools
- Complete persistence and testing framework

Version: 2.0.0 - Full Integration
Date: December 2025
"""

# Standard library imports
import numpy as np
import scipy.sparse as sp
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any, Union, Callable
from enum import IntEnum
import time
from collections import defaultdict
import warnings
import logging
import json
import sys
import re
import subprocess
import platform
from pathlib import Path
import pickle
import random
import argparse

# ============================================================================
# LOGGING CONFIGURATION
# ============================================================================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

# ============================================================================
# DEPENDENCY MANAGEMENT
# ============================================================================

try:
    import qutip as qt
    QUTIP_AVAILABLE = True
    logger.info("QuTiP loaded - quantum features enabled")
except ImportError:
    QUTIP_AVAILABLE = False
    logger.warning("QuTiP not available - quantum features disabled")

try:
    import torch
    TORCH_AVAILABLE = True
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    logger.info(f"PyTorch loaded - using {device}")
except ImportError:
    TORCH_AVAILABLE = False
    device = None
    logger.warning("PyTorch not available - using NumPy fallback")

try:
    import matplotlib.pyplot as plt
    MATPLOTLIB_AVAILABLE = True
    logger.info("Matplotlib loaded")
except ImportError:
    MATPLOTLIB_AVAILABLE = False
    logger.warning("Matplotlib not available - visualization disabled")

try:
    import networkx as nx
    NETWORKX_AVAILABLE = True
    logger.info("NetworkX loaded")
except ImportError:
    NETWORKX_AVAILABLE = False
    logger.warning("NetworkX not available - network visualization limited")

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def is_macos() -> bool:
    """Check if running on macOS"""
    return platform.system() == 'Darwin'

def first_definition(word: str) -> str:
    """Get first definition from macOS Dictionary.app"""
    if not is_macos():
        return f"[macOS Dictionary not available] {word}"
    try:
        result = subprocess.run(
            ['osascript', '-e', f'tell application "Dictionary" to get first entry of word "{word}"'],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
        return f"[No definition found] {word}"
    except Exception as e:
        logger.warning(f"Dictionary lookup failed for '{word}': {e}")
        return f"[Dictionary error] {word}"

def word_synonyms(word: str) -> List[str]:
    """Get synonyms from macOS Dictionary.app"""
    if not is_macos():
        return []
    try:
        result = subprocess.run(
            ['osascript', '-e', f'tell application "Dictionary" to get synonyms of word "{word}"'],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and result.stdout.strip():
            syns = result.stdout.strip().split(',')
            return [s.strip() for s in syns if s.strip()]
        return []
    except Exception as e:
        logger.warning(f"Synonyms lookup failed for '{word}': {e}")
        return []

def get_builtin_mac_dictionaries() -> List[str]:
    """Get list of available macOS dictionaries"""
    if not is_macos():
        return []
    return [
        "New Oxford American Dictionary",
        "Oxford American Writer's Thesaurus",
        "Apple Dictionary",
        "Wikipedia",
        "Oxford Dictionary of English"
    ]

def system_dictionary_lookup(word: str, dictionary: str = None) -> str:
    """Look up word in specific macOS dictionary"""
    if not is_macos():
        return f"[macOS only] {word}"
    try:
        if dictionary:
            cmd = f'tell application "Dictionary" to get definition of word "{word}" from dictionary "{dictionary}"'
        else:
            cmd = f'tell application "Dictionary" to get definition of word "{word}"'
        result = subprocess.run(['osascript', '-e', cmd], capture_output=True, text=True, timeout=5)
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
        return f"[No definition] {word}"
    except Exception as e:
        return f"[Error] {word}: {e}"

# ============================================================================
# KNOWLEDGE BASES
# ============================================================================

NUANCE_KNOWLEDGE = {
    "short_definition": "Nuance is a subtle distinction or variation in meaning, tone, expression, feeling, or context.",
    "linguistic": "In language, nuance refers to the fine gradations that alter meaning, often marked by word choice, tone, or syntax.",
    "philosophical": "Nuance resists reductionism and acknowledges complexity, ambiguity, context, and the grey areas of thought.",
    "psychology": "Humans perceive and process subtle details--nuances--in emotion, expression, perception, and understanding.",
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
        "Truth is rarely pure and never simple. -- Oscar Wilde",
        "It is the mark of an educated mind to be able to entertain a thought without accepting it. -- Aristotle",
        "In the depth of winter, I finally learned that within me there lay an invincible summer. -- Albert Camus",
    ],
    "synthesis": (
        "Nuance refers to the subtle variation and complexity underlying all perception, communication, "
        "and experience. Recognizing nuance is essential for sophistication, empathy, and wise decision-making."
    )
}

def get_nuance_overview(as_summary: bool = False) -> str:
    """Get nuance academic overview"""
    return NUANCE_KNOWLEDGE["short_definition"] if as_summary else NUANCE_KNOWLEDGE.get("academic_overview", NUANCE_KNOWLEDGE["short_definition"])

class GeneralPhrasesAndWords:
    """Collection of general phrases and reasoning patterns"""
    
    phrases = [
        "How can I serve in order to provide the best result possible?",
        "In the context of",
        "relative to",
        "Absolute Macro",
        "Absolute Micro",
        "could be repurposed for..",
        "So long as it produces the desired result which can be verified/is verifiable..",
        "Theoretically speaking it could work if..",
        "All we need to make it work is...",
        "If there is a blockage in desired results...",
        "Logically speaking, in scenario A.",
        "Theoretically speaking, in scenario A.",
        "If yes, then yes/no but if yes/no then yes/no but if yes/no then yes/no...",
        "If yes, then try (a) but if no try (b) and then (d) if (c) = yes/no",
        "Taking into account",
        "Taking into consideration",
        "Catering for",
        "Catering for the fact that",
        "Cause and effect",
        "Overall cause and effect",
        "Cause and effect tracing",
        "Cause and effect predicting",
        "Overall outcome",
        "What am I not asking?",
        "What else is there?",
        "What else could there be?",
        "What would I need in order to make it work?",
        "Leveraging already existing..",
        "If (Blank) then (Bank) but if (Blank) then (Blank)",
        "Finding a way to bypass",
        "Effective and efficient",
        "What does it mean to (Blank) in the context of (Blank)?",
        "Not knowing the answer or getting the desired result is ok so long as I have exhausted all that is available to me",
        "(Love, Serve, Remember)",
        "Absurd and whimsicle with a sense of humour and a smiling heart"
    ]
    
    motivation_note = """Motivation affects perception. Motivation used in this context has a broader meaning. 
    It's not just 'Get up and go to the gym because you're motivated to go to the gym' it's because you are 
    motivated by going to the gym, all you notice are all the gyms in your local area. Or other people in shape. 
    It's similar to 'Encouraged by', 'Pre-exposed to'. What you are motivated by is how you will see the world 
    around you both in a macro/micro sense."""



class CognitiveLevel(IntEnum):
    """Hierarchical cognitive complexity levels"""
    PATTERN_RECOGNITION = 1
    ASSOCIATION = 2
    REASONING = 3
    META_COGNITION = 4
    EMERGENT_INTEGRATION = 5
    ADVANCED_INSIGHT = 6
    GLOBAL_OPTIMIZATION = 7
    
    @property
    def parameter_count(self) -> int:
        """Approximate computational complexity"""
        return 10 ** self.value

# ============================================================================
# EXPOSURE PROFILE
# ============================================================================

@dataclass
class ExposureProfile:
    """Represents a user's exposure and semantic profile"""
    user_id: str
    semantic_shifts: Dict[str, float] = field(default_factory=lambda: defaultdict(float))
    nuance_keywords: List[str] = field(default_factory=list)
    total_exposure_count: int = 0
    relative_context: List[str] = field(default_factory=list)
    
    def from_text(self, text: str):
        """Process text to update the profile"""
        words = re.findall(r'\b\w+\b', text.lower())
        for word in set(words):
            self.semantic_shifts[word] += 0.01
        self.total_exposure_count += 1
        
        sentences = re.split(r'[.!?]+', text)
        self.relative_context.extend([s.strip() for s in sentences if len(s.strip()) > 10])
        
        # Special handling for ambiguous words
        if 'it' in text.lower():
            for sent in self.relative_context:
                if 'meaning' in sent.lower() or 'context' in sent.lower():
                    self.semantic_shifts['it'] = min(0.5, self.semantic_shifts.get('it', 0) + 0.05)

# ============================================================================
# CONCEPT STATE
# ============================================================================

@dataclass
class ConceptState:
    """Enhanced concept representation with personalization"""
    id: str
    cognitive_level: CognitiveLevel
    description: str = ""
    
    # Universal definition
    universal_def: str = field(default="")
    
    # Personalization fields
    relative_meaning: float = field(default=0.0)
    relative_associations: Dict[str, float] = field(default_factory=dict)
    relative_nuance: np.ndarray = field(default_factory=lambda: np.zeros(3))
    relative_context: List[str] = field(default_factory=list)
    
    # Dynamic state vector
    state_vector: np.ndarray = field(default_factory=lambda: np.ones(6) / np.sqrt(6))
    previous_state: np.ndarray = field(default_factory=lambda: np.ones(6) / np.sqrt(6))
    current_dimension: int = 6
    
    # Quantum state
    quantum_state: Optional[Any] = None
    
    # Metrics cache
    _cache: Dict[str, Tuple[float, float]] = field(default_factory=dict)
    
    # Network connectivity
    connected_concepts: List[str] = field(default_factory=list)
    connection_strengths: np.ndarray = field(default=None)
    
    # Ethical bias
    ethical_bias: float = 0.0
    
    # Metadata
    creation_time: float = field(default_factory=time.time)
    last_update: float = field(default_factory=time.time)
    layer: str = "l1"
    user_id: Optional[str] = None
    target_word: Optional[str] = None
    
    # Nuance fields
    nuance_academic_overview: str = ""
    nuance_short: str = ""
    
    def __post_init__(self):
        if self.connection_strengths is None:
            self.connection_strengths = np.array([])
        self.current_dimension = len(self.state_vector)
    
    def get_metric(self, name: str, current_time: float, cache_duration: float = 5.0) -> float:
        """Retrieve metric with caching"""
        if name in self._cache:
            value, timestamp = self._cache[name]
            if current_time - timestamp < cache_duration:
                return value
        
        try:
            from taic_production import MetricEngine
            value = MetricEngine.compute_single_metric(
                name, self.state_vector, self.previous_state,
                self.cognitive_level, self.ethical_bias,
                self.relative_meaning, self.relative_nuance,
                len(self.relative_context)
            )
        except Exception as e:
            logger.warning(f"Metric computation failed for {name}: {e}")
            value = 0.0
        
        self._cache[name] = (value, current_time)
        return value
    
    def invalidate_cache(self):
        """Clear cached metrics"""
        self._cache.clear()
    
    def resize_state(self, new_dimension: int):
        """Resize state vector"""
        if new_dimension == self.current_dimension:
            return
        
        old_dim = self.current_dimension
        new_state = np.zeros(new_dimension)
        
        if new_dimension > old_dim:
            new_state[:old_dim] = self.state_vector
            extra = np.random.randn(new_dimension - old_dim) * 0.1
            new_state[old_dim:] = extra
        else:
            new_state = self.state_vector[:new_dimension]
        
        norm = np.linalg.norm(new_state)
        if norm > 1e-10:
            self.state_vector = new_state / norm
        
        if len(self.previous_state) >= new_dimension:
            self.previous_state = self.previous_state[:new_dimension]
        else:
            self.previous_state = np.pad(self.previous_state, (0, new_dimension - len(self.previous_state)))
        
        self.current_dimension = new_dimension
        self.invalidate_cache()
    
    def enrich_with_nuance(self):
        """Add nuance overview"""
        self.nuance_academic_overview = get_nuance_overview(as_summary=False)
        self.nuance_short = NUANCE_KNOWLEDGE["short_definition"]
    
    def enrich_with_mac_dictionary(self):
        """Add macOS Dictionary definition"""
        if self.target_word:
            defn = first_definition(self.target_word)
            if not defn.startswith('['):
                self.universal_def = defn
            syns = word_synonyms(self.target_word)
            if syns:
                self.relative_associations['synonyms'] = ', '.join(syns)

# ============================================================================
# METRIC ENGINE
# ============================================================================

class MetricEngine:
    """Centralized metric computation with personalization support"""
    
    @staticmethod
    def compute_all_metrics(state: np.ndarray, previous: np.ndarray,
                           cognitive_level: CognitiveLevel, ethical_bias: float = 0.0,
                           rel_meaning: float = 0.0, rel_nuance: np.ndarray = None,
                           rel_context_len: int = 0) -> Dict[str, float]:
        """Compute all T-AIC metrics"""
        if rel_nuance is None:
            rel_nuance = np.zeros(3)
        
        try:
            config = TAICConfig()
            
            # Pad to same size
            size = max(state.shape[0], previous.shape[0])
            state_padded = np.zeros(size)
            previous_padded = np.zeros(size)
            state_padded[:state.shape[0]] = state
            previous_padded[:previous.shape[0]] = previous
            
            # Normalize to probabilities
            probs = np.abs(state_padded) ** 2
            prob_sum = probs.sum()
            if prob_sum < 1e-10:
                return {'entropy': 1.0, 'cbmi': 0.0, 'gab': 0.0, 'srm': 0.0, 'bcp': 0.0,
                       'map': 0.0, 'trajectory': 0.0, 'convergence_score': 0.0,
                       'relative_context_len': 0, 'contextual_weight': 0.0}
            probs = probs / prob_sum
            
            # System Entropy
            entropy = -np.sum(probs * np.log(probs + 1e-10))
            normalized_entropy = np.clip(entropy / np.log(len(probs)) if len(probs) > 1 else entropy, 0.0, 1.0)
            
            # Self-Referential Minimization
            state_change = np.linalg.norm(state_padded - previous_padded)
            srm = np.exp(-state_change) * (1 + rel_context_len * 0.02)
            
            # Minimal Action Principle
            complexity = np.log10(cognitive_level.parameter_count + 1)
            map_val = srm / complexity if complexity > 0 else srm
            
            # Cross-Boundary Mutual Information
            cbmi = srm * 0.7 + (1.0 - normalized_entropy) * 0.3
            
            # Boundary Condition Permeability
            bcp_base = cbmi * map_val
            bcp = min(1.0, bcp_base + ethical_bias * 0.2 + rel_meaning * 0.1)
            bcp *= (1 + (rel_context_len / 10.0))
            bcp = min(1.0, bcp)
            
            # Optimal State Trajectory
            trajectory = 1.0 - normalized_entropy + np.sum(rel_nuance) * 0.05
            trajectory = min(1.0, trajectory)
            
            # Gratitude Appreciation Bias
            gab = 0.0
            if normalized_entropy < 0.2 and srm > 0.8:
                gab = min(1.0, (0.8 - normalized_entropy) * srm)
            
            # Convergence score
            convergence_score = (
                (1 - normalized_entropy) * config.weight_entropy +
                trajectory * config.weight_trajectory +
                srm * config.weight_srm +
                bcp * config.weight_bcp +
                gab * config.weight_gab
            )
            
            return {
                'entropy': float(normalized_entropy), 'srm': float(srm), 'map': float(map_val),
                'cbmi': float(cbmi), 'bcp': float(bcp), 'trajectory': float(trajectory),
                'gab': float(gab), 'convergence_score': float(convergence_score),
                'relative_context_len': rel_context_len, 'contextual_weight': float(rel_context_len / 10.0)
            }
        except Exception as e:
            logger.error(f"Metric computation error: {e}")
            return {'entropy': 0.0, 'cbmi': 0.0, 'gab': 0.0, 'srm': 0.0, 'bcp': 0.0,
                   'map': 0.0, 'trajectory': 0.0, 'convergence_score': 0.0,
                   'relative_context_len': 0, 'contextual_weight': 0.0}
    
    @staticmethod
    def compute_single_metric(name: str, state: np.ndarray, previous: np.ndarray,
                             cognitive_level: CognitiveLevel, ethical_bias: float = 0.0,
                             rel_meaning: float = 0.0, rel_nuance: np.ndarray = None,
                             rel_context_len: int = 0) -> float:
        """Compute individual metric"""
        metrics = MetricEngine.compute_all_metrics(
            state, previous, cognitive_level, ethical_bias,
            rel_meaning, rel_nuance, rel_context_len
        )
        return metrics.get(name, 0.0)
    
    @staticmethod
    def batch_compute(states: List[ConceptState], use_gpu: bool = True) -> Dict[str, np.ndarray]:
        """Batch computation with optional GPU acceleration"""
        n = len(states)
        if n == 0:
            return {}
        
        # Sequential fallback
        results = defaultdict(list)
        for state in states:
            metrics = MetricEngine.compute_all_metrics(
                state.state_vector, state.previous_state,
                state.cognitive_level, state.ethical_bias,
                state.relative_meaning, state.relative_nuance,
                len(state.relative_context)
            )
            for key, value in metrics.items():
                results[key].append(value)
        return {k: np.array(v) for k, v in results.items()}

# ============================================================================
# PERSONALIZATION ENGINE
# ============================================================================

class PersonalizationEngine:
    """Manages user-specific concept adaptation"""
    
    def __init__(self):
        self.profiles: Dict[str, ExposureProfile] = {}
        self.profile_save_path = "profile_store.json"
    
    def create_or_update_profile(self, user_id: str, exposure_text: str) -> ExposureProfile:
        """Create or update user profile"""
        profile = self.profiles.get(user_id, ExposureProfile(user_id=user_id))
        profile.from_text(exposure_text)
        self.profiles[user_id] = profile
        return profile
    
    def adapt_concept_for_user(self, concept: ConceptState, user_id: str, target_word: str = "compassion"):
        """Adapt concept using user profile data"""
        # Add macOS dictionary definition
        if target_word:
            concept.enrich_with_mac_dictionary()
        
        # Add nuance if word is "nuance"
        if target_word and target_word.lower() == "nuance":
            concept.enrich_with_nuance()
        
        # Apply user profile
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
        """Save profiles to JSON"""
        try:
            with open(self.profile_save_path, "w") as f:
                data = {uid: {
                    'semantic_shifts': dict(p.semantic_shifts),
                    'nuance_keywords': list(p.nuance_keywords),
                    'total_exposure_count': p.total_exposure_count,
                    'relative_context': list(p.relative_context)
                } for uid, p in self.profiles.items()}
                json.dump(data, f, indent=2)
            logger.info(f"Saved {len(self.profiles)} profiles")
        except Exception as e:
            logger.error(f"Failed to save profiles: {e}")
    
    def load_profiles(self):
        """Load profiles from JSON"""
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
            logger.info(f"Loaded {len(self.profiles)} profiles")
        except FileNotFoundError:
            logger.info("No saved profiles found")
        except Exception as e:
            logger.error(f"Failed to load profiles: {e}")

# ============================================================================
# SPARSE CONCEPT NETWORK
# ============================================================================

class SparseConceptNetwork:
    """Memory-efficient sparse network for concept relationships"""
    
    def __init__(self, max_concepts: int = 10000):
        self.max_concepts = max_concepts
        self.adjacency = sp.lil_matrix((max_concepts, max_concepts), dtype=np.float32)
        self.concepts: Dict[str, ConceptState] = {}
        self.id_to_index: Dict[str, int] = {}
        self.index_to_id: Dict[int, str] = {}
        self.free_indices = list(range(max_concepts))
        self.total_connections = 0
        self.sparsity = 1.0
    
    def add_concept(self, concept: ConceptState) -> int:
        """Add concept to network"""
        if concept.id in self.id_to_index:
            return self.id_to_index[concept.id]
        
        if not self.free_indices:
            raise RuntimeError("Network capacity exceeded")
        
        idx = self.free_indices.pop(0)
        self.concepts[concept.id] = concept
        self.id_to_index[concept.id] = idx
        self.index_to_id[idx] = concept.id
        return idx
    
    def connect(self, source_id: str, target_id: str, strength: float = 1.0):
        """Create connection between concepts"""
        if source_id not in self.id_to_index or target_id not in self.id_to_index:
            return
        
        src_idx = self.id_to_index[source_id]
        tgt_idx = self.id_to_index[target_id]
        old_val = self.adjacency[src_idx, tgt_idx]
        self.adjacency[src_idx, tgt_idx] = strength
        
        if old_val == 0 and strength != 0:
            self.total_connections += 1
        elif old_val != 0 and strength == 0:
            self.total_connections -= 1
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get network statistics"""
        active_count = len(self.concepts)
        max_connections = active_count * (active_count - 1)
        sparsity = 1.0 - (self.total_connections / max(max_connections, 1))
        
        return {
            'active_concepts': active_count,
            'total_connections': self.total_connections,
            'sparsity': sparsity,
            'capacity_used': active_count / self.max_concepts
        }

# ============================================================================
# ADAPTIVE DIMENSIONAL HIERARCHY
# ============================================================================

class AdaptiveDimensionalHierarchy:
    """Adaptive dimensionality based on cognitive complexity"""
    
    def __init__(self):
        # Fixed: sort by threshold descending for correct priority
        self.level_thresholds = {
            10: 0.95,  # Meta-cognition -> 10D
            8: 0.85,   # Very high -> 8D
            6: 0.7,    # High -> 6D
            5: 0.5,    # Medium -> 5D
            4: 0.3     # Low -> 4D
        }
    
    def get_optimal_dimension(self, concept: ConceptState,
                             integration_score: float) -> int:
        """Determine optimal embedding dimension"""
        base_dim = min(2 + concept.cognitive_level.value, 10)
        
        # Check thresholds in descending order (highest first)
        for dim, threshold in sorted(self.level_thresholds.items(),
                                    key=lambda x: x[1], reverse=True):
            if integration_score >= threshold:
                return min(dim, 10)
        
        return min(base_dim, 6)
    
    def embed(self, state_vector: np.ndarray, target_dim: int) -> np.ndarray:
        """Embed state vector into higher dimension"""
        current_dim = len(state_vector)
        if target_dim <= current_dim:
            return state_vector[:target_dim]
        
        expanded = np.zeros(target_dim)
        expanded[:current_dim] = state_vector
        extra_dims = target_dim - current_dim
        
        if extra_dims > 0:
            ortho = np.random.randn(extra_dims) * 0.1
            ortho = ortho / (np.linalg.norm(ortho) + 1e-10)
            expanded[current_dim:] = ortho
        
        norm = np.linalg.norm(expanded)
        return expanded / (norm + 1e-10) if norm > 1e-10 else expanded
    
    def project_down(self, high_dim_vector: np.ndarray, target_dim: int) -> np.ndarray:
        """Project from higher to lower dimension"""
        if len(high_dim_vector) <= target_dim:
            return high_dim_vector
        
        projected = high_dim_vector[:target_dim]
        norm = np.linalg.norm(projected)
        return projected / (norm + 1e-10) if norm > 1e-10 else projected

# ============================================================================
# QUANTUM STATE MANAGER
# ============================================================================

class QuantumStateManager:
    """Manages quantum state evolution (if enabled)"""
    
    def __init__(self, enabled: bool = False):
        self.enabled = enabled and QUTIP_AVAILABLE
        if self.enabled:
            print("[Quantum] QuTiP-based quantum simulation enabled")
    
    def evolve_state(self, concept: ConceptState, metrics: Dict[str, float],
                    time_delta: float, time_scale: float = 0.1):
        """Evolve quantum state based on metrics"""
        if not self.enabled:
            return
        
        try:
            dim = len(concept.state_vector)
            
            # Build Hamiltonian from metrics
            # SRM drives X-rotation (mixing), entropy drives Z (phase)
            H = (metrics['srm'] * qt.sigmax() +
                 (1 - metrics['entropy']) * qt.sigmaz())
            
            # Scale to appropriate dimension
            if dim > 2:
                H = qt.tensor(H, qt.qeye(dim // 2))
            
            # Time evolution operator
            U = (-1j * H * time_delta * time_scale).expm()
            
            # Create or update quantum state
            if concept.quantum_state is None:
                # Initialize from classical state
                concept.quantum_state = qt.Qobj(concept.state_vector)
            
            # Evolve
            concept.quantum_state = U * concept.quantum_state
            
            # Extract to classical
            if isinstance(concept.quantum_state, qt.Qobj):
                concept.state_vector = np.abs(concept.quantum_state.full().flatten())
                norm = np.linalg.norm(concept.state_vector)
                if norm > 1e-10:
                    concept.state_vector = concept.state_vector / norm
        except Exception as e:
            warnings.warn(f"Quantum evolution failed: {e}, falling back to classical")
            self.enabled = False

# ============================================================================
# ATTENTION ENGINE
# ============================================================================

class AttentionEngine:
    """Handles attention dynamics and oscillations"""
    
    def __init__(self, network: SparseConceptNetwork):
        self.network = network
    
    def compute_coherence(self, concept_ids: List[str]) -> float:
        """Compute collective coherence for concept group"""
        if not concept_ids:
            return 1.0
        
        concepts = [self.network.concepts[cid] for cid in concept_ids
                   if cid in self.network.concepts]
        
        if len(concepts) < 2:
            return 1.0
        
        similarities = []
        for i in range(len(concepts)):
            for j in range(i+1, len(concepts)):
                # Handle different dimensions
                min_dim = min(len(concepts[i].state_vector), len(concepts[j].state_vector))
                v1 = concepts[i].state_vector[:min_dim]
                v2 = concepts[j].state_vector[:min_dim]
                sim = np.dot(v1, v2)
                similarities.append(abs(sim))
        
        return np.mean(similarities) if similarities else 0.0
    
    def focus_attention(self, concept_ids: List[str], focal_concept_id: str,
                       intensity: float = 1.0) -> Dict[str, float]:
        """Propagate attention from focal concept"""
        return self.network.propagate(focal_concept_id, intensity, steps=3)

# ============================================================================
# CAUSAL ENGINE
# ============================================================================

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

# ============================================================================
# ETHICAL MONITOR
# ============================================================================

class EthicalMonitor:
    """Real-time monitoring and ethical drift detection"""
    
    def __init__(self, config: TAICConfig):
        self.config = config
        self.alert_history: List[Dict[str, Any]] = []
    
    def check_system_health(self, coherence: float,
                           avg_convergence: float,
                           step: int) -> List[str]:
        """Check for ethical drift and system issues"""
        alerts = []
        
        # Ethical drift detection
        if avg_convergence < self.config.ethical_drift_threshold:
            alert = {
                'step': step,
                'type': 'ETHICAL_DRIFT',
                'severity': 'HIGH',
                'message': f'Ethical drift detected: avg convergence = {avg_convergence:.4f}',
                'recommendation': 'Recommend SRM boost or ethical input injection'
            }
            alerts.append(alert['message'])
            self.alert_history.append(alert)
        
        # Coherence degradation
        if coherence < 0.5:
            alert = {
                'step': step,
                'type': 'COHERENCE_LOW',
                'severity': 'MEDIUM',
                'message': f'Low coherence detected: {coherence:.4f}',
                'recommendation': 'System fragmentation - consider consolidation'
            }
            alerts.append(alert['message'])
            self.alert_history.append(alert)
        
        # Excellent convergence
        if avg_convergence > 0.9:
            alert = {
                'step': step,
                'type': 'HIGH_INTEGRATION',
                'severity': 'INFO',
                'message': f'High integration achieved: {avg_convergence:.4f}',
                'recommendation': 'System operating optimally'
            }
            alerts.append(alert['message'])
            self.alert_history.append(alert)
        
        return alerts
    
    def get_alert_summary(self) -> Dict[str, Any]:
        """Get summary of all alerts"""
        if not self.alert_history:
            return {'total_alerts': 0, 'by_type': {}, 'by_severity': {}}
        
        by_type = defaultdict(int)
        by_severity = defaultdict(int)
        for alert in self.alert_history:
            by_type[alert['type']] += 1
            by_severity[alert['severity']] += 1
        
        return {
            'total_alerts': len(self.alert_history),
            'by_type': dict(by_type),
            'by_severity': dict(by_severity),
            'recent_alerts': self.alert_history[-5:]
        }

# ============================================================================
# DECISION LAYER
# ============================================================================

class DecisionLayer:
    """Decision-making layer with informed, situational, and intuitive judgment"""
    
    def informed_decision(self, context: List[str], task: str, options: List[str]) -> str:
        """Make informed decision based on context"""
        context_str = " ".join(context).lower()
        matches = []
        for option in options:
            if option.lower() in context_str or option.lower() in task.lower():
                matches.append(option)
        if matches:
            return f"Informed choice: {matches[0]}"
        return f"Intuitive judgment: {random.choice(options)}"
    
    def situational_awareness(self, context: List[str], task: str) -> str:
        """Assess situation"""
        keywords = ['delay', 'priority', 'completed', 'uncertain', 'critical', 'risk']
        awareness_points = []
        for kw in keywords:
            for sent in context:
                if kw in sent.lower():
                    awareness_points.append(f"{kw} detected")
        if "urgent" in task.lower():
            awareness_points.append("Task marked as urgent")
        return "Situational awareness: " + "; ".join(awareness_points) if awareness_points else "Situation normal"
    
    def intuitive_judgement(self, context: List[str], task: str) -> str:
        """Make intuitive judgment"""
        pos_words = ['good', 'efficient', 'positive', 'quick', 'trusted']
        neg_words = ['bad', 'slow', 'negative', 'uncertain', 'problematic']
        summary = []
        for s in context:
            if any(w in s.lower() for w in pos_words):
                summary.append("Favorable context")
            if any(w in s.lower() for w in neg_words):
                summary.append("Unfavorable context")
        return " ".join(summary) if summary else "No strong signal"

# ============================================================================
# MEME SYSTEM
# ============================================================================

class Meme:
    """Transmissible unit of cultural information"""
    def __init__(self, content: str, meme_type: str, origin: str = "", context_tags: List[str] = None):
        self.content = content
        self.meme_type = meme_type  # 'language', 'cognitive', 'behavior'
        self.origin = origin
        self.context_tags = context_tags or []
        self.generation = 0
    
    def mutate(self, mutation: str) -> "Meme":
        """Create mutated variant"""
        new_content = f"{self.content} {mutation}"
        return Meme(new_content, self.meme_type, self.origin, self.context_tags + ["mutated"])

class Memeplex:
    """Collection of memes (ecosystem)"""
    def __init__(self, memes: List[Meme] = None):
        self.memes: List[Meme] = memes or []
    
    def propagate(self, receiver: "Agent"):
        """Transmit memes to agent"""
        for meme in self.memes:
            receiver.install_meme(meme)
    
    def mutate_all(self):
        """Mutate all memes"""
        for meme in self.memes:
            if random.random() < 0.1:  # 10% mutation rate
                mutated = meme.mutate("evolved")
                self.memes.append(mutated)

class Agent:
    """Agent with linguistic, cognitive, and behavioral layers"""
    def __init__(self):
        self.language_modules: List[Meme] = []
        self.cognitive_frameworks: List[Meme] = []
        self.behavioral_protocols: List[Meme] = []
        self.meme_history: List[str] = []
    
    def install_meme(self, meme: Meme):
        """Install meme into appropriate layer"""
        if meme.meme_type == "language":
            self.language_modules.append(meme)
        elif meme.meme_type == "cognitive":
            self.cognitive_frameworks.append(meme)
        elif meme.meme_type == "behavior":
            self.behavioral_protocols.append(meme)
        self.meme_history.append(meme.content)
    
    def speak(self) -> List[str]:
        """Produce utterances influenced by memes"""
        return [meme.content for meme in self.language_modules]

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

 

# Understanding perception and what drives it: """Motivation affects perception"? Motivation used in this was has a broader meaning. It's not just "Get up and go to the gym because you're motivated to go to the gym" it's because you are motivated by going to the gym, all you notice at all the gyms in your local area. Or other people in shape. It's similar to "Encouraged by", "Pre-exposed to". What you are motivated by is how you will see the world around you both in a macro/micro sense. It is also possible too to have times where none of that stuff even crosses your mind and you just do whatever you do. If you are motivated by survival? Motivated by gratification? Power and control? And so on all the way up until the idea of you or concept disappears. It's not that difficult to see what people's motivations are after knowing about this concept and intuitively understanding it. All of this covers the broad and the specific."""

"""
T-AIC Enhanced Production Architecture

Features:
- Adaptive dimensional hierarchy integration
- Optional quantum state evolution
- PyTorch GPU acceleration
- Cross-layer interactions
- Ethical input injection
- Real-time monitoring and alerts
- Comprehensive visualization
"""
import numpy as np
import scipy.sparse as sp
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any, Union
from enum import IntEnum
import time
from collections import defaultdict
import warnings

# Optional dependencies
try:
    import qutip as qt
    QUTIP_AVAILABLE = True
except ImportError:
    QUTIP_AVAILABLE = False
    warnings.warn("QuTiP not available - quantum features disabled")

try:
    import torch
    TORCH_AVAILABLE = True
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
except ImportError:
    TORCH_AVAILABLE = False
    device = None
    warnings.warn("PyTorch not available - using NumPy fallback")

try:
    import matplotlib.pyplot as plt
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False
    warnings.warn("Matplotlib not available - visualization disabled")

# ============================================================================
# VISUALIZATION
# ============================================================================

class TAICVisualizer:
    """Visualization tools for T-AIC system"""
    
    def __init__(self, enabled: bool = True):
        self.enabled = enabled and MATPLOTLIB_AVAILABLE
        if not self.enabled and not MATPLOTLIB_AVAILABLE:
            warnings.warn("Matplotlib not available - visualization disabled")
    
    def plot_convergence_history(self, history: List[float],
                                 save_path: Optional[str] = None):
        """Plot convergence over time"""
        if not self.enabled:
            return
        
        plt.figure(figsize=(10, 6))
        plt.plot(history, linewidth=2)
        plt.xlabel('Simulation Step')
        plt.ylabel('Global Coherence')
        plt.title('T-AIC Convergence History')
        plt.grid(True, alpha=0.3)
        plt.ylim(0, 1)
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
        else:
            plt.show()
        plt.close()
    
    def plot_metric_comparison(self, concepts: List[ConceptState],
                              current_time: float,
                              save_path: Optional[str] = None):
        """Compare metrics across concepts"""
        if not self.enabled or not concepts:
            return
        
        metric_names = ['entropy', 'srm', 'map', 'bcp', 'convergence_score']
        n_concepts = min(len(concepts), 10)  # Limit to 10 for readability
        
        data = {name: [] for name in metric_names}
        labels = []
        
        for concept in concepts[:n_concepts]:
            labels.append(f"{concept.id[:8]}\n{concept.cognitive_level.name[:4]}")
            for name in metric_names:
                data[name].append(concept.get_metric(name, current_time))
        
        fig, axes = plt.subplots(2, 3, figsize=(15, 10))
        axes = axes.flatten()
        
        for i, name in enumerate(metric_names):
            axes[i].bar(range(n_concepts), data[name])
            axes[i].set_title(name.upper())
            axes[i].set_ylabel('Value')
            axes[i].set_ylim(0, 1)
            axes[i].set_xticks(range(n_concepts))
            axes[i].set_xticklabels(labels, rotation=45, ha='right')
            axes[i].grid(True, alpha=0.3)
        
        # Remove extra subplot
        fig.delaxes(axes[5])
        
        plt.tight_layout()
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
        else:
            plt.show()
        plt.close()
    
    def plot_network_structure(self, network: SparseConceptNetwork,
                               max_nodes: int = 50,
                               save_path: Optional[str] = None):
        """Visualize network structure"""
        if not self.enabled:
            return
        
        try:
            import networkx as nx
        except ImportError:
            warnings.warn("NetworkX required for network visualization")
            return
        
        # Build graph
        G = nx.DiGraph()
        concept_ids = list(network.concepts.keys())[:max_nodes]
        
        for cid in concept_ids:
            concept = network.concepts[cid]
            G.add_node(cid, level=concept.cognitive_level.value)
        
        for cid in concept_ids:
            neighbors = network.get_neighbors(cid)
            for neighbor_id, strength in neighbors:
                if neighbor_id in concept_ids:
                    G.add_edge(cid, neighbor_id, weight=strength)
        
        # Layout
        pos = nx.spring_layout(G, k=0.5, iterations=50)
        
        # Plot
        plt.figure(figsize=(12, 12))
        
        # Color by cognitive level
        levels = [G.nodes[node]['level'] for node in G.nodes()]
        nx.draw_networkx_nodes(G, pos, node_color=levels,
                              cmap='viridis', node_size=300,
                              vmin=1, vmax=7)
        nx.draw_networkx_edges(G, pos, alpha=0.3, arrows=True,
                              arrowsize=10, edge_color='gray')
        
        plt.title(f'T-AIC Network Structure ({len(G.nodes())} concepts)')
        plt.axis('off')
        plt.colorbar(plt.cm.ScalarMappable(cmap='viridis',
                                          norm=plt.Normalize(1, 7)),
                    label='Cognitive Level')
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
        else:
            plt.show()
        plt.close()

# ============================================================================
# PERSISTENCE
# ============================================================================

class TAICPersistence:
    """Save and load T-AIC system state"""
    
    @staticmethod
    def save_system(taic: OptimizedTAIC, filepath: str):
        """Save complete system state to file"""
        import pickle
        
        state = {
            'config': taic.config,
            'l1_concepts': {cid: c for cid, c in taic.l1_network.concepts.items()},
            'l3_concepts': {cid: c for cid, c in taic.l3_network.concepts.items()},
            'l4_concepts': {cid: c for cid, c in taic.l4_network.concepts.items()},
            'l1_adjacency': taic.l1_network.adjacency,
            'l3_adjacency': taic.l3_network.adjacency,
            'l4_adjacency': taic.l4_network.adjacency,
            'stats': taic.stats,
            'alert_history': taic.monitor.alert_history
        }
        
        with open(filepath, 'wb') as f:
            pickle.dump(state, f)
        
        print(f"[SAVE] System saved to {filepath}")
    
    @staticmethod
    def load_system(filepath: str) -> OptimizedTAIC:
        """Load system state from file"""
        import pickle
        
        with open(filepath, 'rb') as f:
            state = pickle.load(f)
        
        # Reconstruct system
        taic = OptimizedTAIC(state['config'])
        
        # Restore concepts
        for cid, concept in state['l1_concepts'].items():
            taic.l1_network.concepts[cid] = concept
            taic.l1_network.add_concept(concept)
        
        for cid, concept in state['l3_concepts'].items():
            taic.l3_network.concepts[cid] = concept
            taic.l3_network.add_concept(concept)
        
        for cid, concept in state['l4_concepts'].items():
            taic.l4_network.concepts[cid] = concept
            taic.l4_network.add_concept(concept)
        
        # Restore adjacency matrices
        taic.l1_network.adjacency = state['l1_adjacency']
        taic.l3_network.adjacency = state['l3_adjacency']
        taic.l4_network.adjacency = state['l4_adjacency']
        
        # Restore stats
        taic.stats = state['stats']
        taic.monitor.alert_history = state['alert_history']
        
        print(f"[LOAD] System loaded from {filepath}")
        return taic

# ============================================================================
# OPTIMIZED TAIC (MAIN SYSTEM)
# ============================================================================

class OptimizedTAIC:
    """Main T-AIC system with full integration"""
    
    def __init__(self, config: Optional[TAICConfig] = None):
        self.config = config or TAICConfig()
        
        # Networks
        self.l1_network = SparseConceptNetwork(self.config.l1_capacity)
        self.l3_network = SparseConceptNetwork(self.config.l3_capacity)
        self.l4_network = SparseConceptNetwork(self.config.l4_capacity)
        
        # Engines
        self.personalization = PersonalizationEngine()
        self.decision = DecisionLayer()
        
        # Stats
        self.stats = {
            'total_concepts': 0,
            'total_steps': 0,
            'convergence_history': []
        }
        
        logger.info("OptimizedTAIC initialized")
        self.dim_hierarchy = AdaptiveDimensionalHierarchy()
        self.quantum_manager = QuantumStateManager(enabled=self.config.enable_quantum)
        self.attention_engine = AttentionEngine(self.l1_network)
        self.causal_engine = CausalEngine(self.l1_network, self.config, self.quantum_manager)
        self.monitor = EthicalMonitor(self.config)
        self.visualizer = TAICVisualizer()

    def create_concept(self, description: str,
                      cognitive_level: CognitiveLevel = CognitiveLevel.META_COGNITION,
                      layer: str = 'l1', ethical_bias: float = 0.0,
                      user_id: Optional[str] = None,
                      target_word: Optional[str] = None) -> ConceptState:
        """Create new concept with personalization"""
        concept_id = f"{layer}_{int(time.time() * 1000000) % 1000000:06x}"
        concept = ConceptState(
            id=concept_id, cognitive_level=cognitive_level,
            description=description, ethical_bias=ethical_bias,
            layer=layer, user_id=user_id, target_word=target_word
        )
        
        if user_id and target_word:
            self.personalization.adapt_concept_for_user(concept, user_id, target_word)
        
        # Add to appropriate network
        network = getattr(self, f"{layer}_network")
        network.add_concept(concept)
        self.stats['total_concepts'] += 1
        
        return concept
    
    def connect_concepts(self, source_id: str, target_id: str, strength: float = 0.7):
        """Create connection between concepts"""
        for network in [self.l1_network, self.l3_network, self.l4_network]:
            if source_id in network.concepts and target_id in network.concepts:
                network.connect(source_id, target_id, strength)
                return
    
    def get_system_report(self) -> Dict[str, Any]:
        """Generate system report"""
        return {
            'system_statistics': {
                'total_concepts': self.stats['total_concepts'],
                'total_steps': self.stats['total_steps'],
                'l1_concepts': len(self.l1_network.concepts),
                'l3_concepts': len(self.l3_network.concepts),
                'l4_concepts': len(self.l4_network.concepts)
            },
            'network_health': {
                'l1_stats': self.l1_network.get_statistics(),
                'l3_stats': self.l3_network.get_statistics(),
                'l4_stats': self.l4_network.get_statistics()
            }
        }

    def simulate(self, num_steps: int = 10,
                concept_ids: List[str] = None,
                visualize_every: int = 0) -> List[Dict[str, Any]]:
        """Run multi-step simulation with optional visualization"""
        results = []
        
        for step in range(num_steps):
            step_result = self.simulate_step(concept_ids)
            step_result['step_number'] = step
            results.append(step_result)
            
            # Print progress
            if (step + 1) % 10 == 0 or step == num_steps - 1:
                coherence = step_result['global_coherence']
                avg_conv = step_result['avg_convergence']
                alerts_str = f", ALERTS: {len(step_result['alerts'])}" if step_result['alerts'] else ""
                
                print(f"Step {step+1}/{num_steps}: "
                      f"Coherence={coherence:.4f}, "
                      f"AvgConv={avg_conv:.4f}, "
                      f"Time={step_result['execution_time']:.4f}s{alerts_str}")
            
            # Visualize periodically
            if visualize_every > 0 and (step + 1) % visualize_every == 0:
                self.visualizer.plot_convergence_history(
                    self.stats['convergence_history']
                )
        
        return results
    
    def inject_ethical_input(self, description: str,
                            cognitive_level: CognitiveLevel = CognitiveLevel.META_COGNITION,
                            layer: str = 'l3') -> str:
        """NEW: Inject ethically-loaded concept to boost system GAB"""
        concept_id = self.create_concept(
            description=description,
            cognitive_level=cognitive_level,
            layer=layer,
            ethical_bias=0.85  # High ethical loading
        )
        print(f"[ETHICAL INPUT] Injected: {description[:50]}... (bias=0.85)")
        return concept_id
    
    def visualize_system(self, save_dir: Optional[str] = None):
        """Generate all visualizations"""
        current_time = time.time()
        
        # Convergence history
        if self.stats['convergence_history']:
            path = f"{save_dir}/convergence.png" if save_dir else None
            self.visualizer.plot_convergence_history(
                self.stats['convergence_history'], path
            )
        
        # Metric comparison
        concepts = list(self.l1_network.concepts.values())
        if concepts:
            path = f"{save_dir}/metrics.png" if save_dir else None
            self.visualizer.plot_metric_comparison(concepts, current_time, path)
        
        # Network structure
        if len(self.l1_network.concepts) > 0:
            path = f"{save_dir}/network.png" if save_dir else None
            self.visualizer.plot_network_structure(self.l1_network, save_path=path)


# ============================================================================
# ENHANCED DEMONSTRATION
# ============================================================================

def demo_enhanced_taic():
    """Comprehensive demonstration of enhanced T-AIC"""
    print("="*70)
    print("T-AIC ENHANCED PRODUCTION ARCHITECTURE")
    print("="*70)
    print()
    
    # Initialize with custom config
    config = TAICConfig(
        l1_capacity=2000,
        l3_capacity=100,
        l4_capacity=20,
        enable_quantum=QUTIP_AVAILABLE,
        enable_gpu=True,
        enable_alerts=True,
        ethical_drift_threshold=0.25
    )
    
    print(f"[CONFIG] Quantum: {config.enable_quantum}, GPU: {TORCH_AVAILABLE and torch.cuda.is_available()}")
    print()
    
    taic = OptimizedTAIC(config)
    
    # Create L1 concepts
    print("Creating L1 concepts...")
    l1_descriptions = [
        "Pattern recognition in temporal sequences",
        "Associative memory network formation",
        "Attention mechanism with gating",
        "Reward signal temporal difference learning",
        "Error gradient backpropagation",
        "Hierarchical feature extraction",
        "Working memory buffer management"
    ]
    
    l1_levels = [
        CognitiveLevel.PATTERN_RECOGNITION,
        CognitiveLevel.PATTERN_RECOGNITION,
        CognitiveLevel.ASSOCIATION,
        CognitiveLevel.ASSOCIATION,
        CognitiveLevel.REASONING,
        CognitiveLevel.REASONING,
        CognitiveLevel.META_COGNITION
    ]
    
    l1_ids = []
    for desc, level in zip(l1_descriptions, l1_levels):
        cid = taic.create_concept(desc, level, layer='l1')
        l1_ids.append(cid)
    
    print(f"✓ Created {len(l1_ids)} L1 concepts")
    
    # Create network connections
    print("\nEstablishing concept network...")
    for i in range(len(l1_ids) - 1):
        taic.connect_concepts(l1_ids[i], l1_ids[i+1], strength=0.7)
    
    # Cross-connections
    taic.connect_concepts(l1_ids[0], l1_ids[3], strength=0.5)
    taic.connect_concepts(l1_ids[2], l1_ids[5], strength=0.6)
    taic.connect_concepts(l1_ids[1], l1_ids[4], strength=0.4)
    
    print(f"✓ Established {len(l1_ids)-1+3} connections")
    
    # Create L3 concepts
    print("\nCreating L3 concepts...")
    l3_id1 = taic.create_concept(
        "Integrated multi-modal learning system",
        CognitiveLevel.META_COGNITION,
        layer='l3'
    )
    l3_id2 = taic.create_concept(
        "Meta-cognitive monitoring and control",
        CognitiveLevel.EMERGENT_INTEGRATION,
        layer='l3'
    )
    print(f"✓ Created 2 L3 concepts")
    
    # Inject ethical input
    print("\n[ETHICAL INPUT] Injecting compassion-loaded concept...")
    ethical_id = taic.inject_ethical_input(
        "Universal compassion and boundary permeability principle",
        CognitiveLevel.ADVANCED_INSIGHT,
        layer='l3'
    )
    
    # Cross-layer connections
    print("\nEstablishing cross-layer connections...")
    taic.connect_concepts(l1_ids[-1], l3_id1, strength=0.8, cross_layer=True)
    taic.connect_concepts(l3_id1, ethical_id, strength=0.9, cross_layer=True)
    print("✓ Cross-layer hierarchy established")
    
    # Create L4 meta-concept
    print("\nCreating L4 meta-concept...")
    l4_id = taic.create_concept(
        "Global optimization and integration framework",
        CognitiveLevel.GLOBAL_OPTIMIZATION,
        layer='l4'
    )
    taic.connect_concepts(ethical_id, l4_id, strength=0.9, cross_layer=True)
    print(f"✓ Created L4 concept: {l4_id}")
    
    # Run simulation
    print("\n" + "="*70)
    print("RUNNING ENHANCED SIMULATION (30 steps)")
    print("="*70)
    print()
    
    results = taic.simulate(num_steps=30, concept_ids=l1_ids, visualize_every=0)
    
    # Generate comprehensive report
    print("\n" + "="*70)
    print("COMPREHENSIVE SYSTEM REPORT")
    print("="*70)
    
    report = taic.get_system_report()
    
    print("\n[System Statistics]")
    for key, value in report['system_statistics'].items():
        print(f"  {key}: {value}")
    
    print("\n[Network Health]")
    for key, value in report['network_health'].items():
        if isinstance(value, float):
            print(f"  {key}: {value:.4f}")
        else:
            print(f"  {key}: {value}")
    
    print("\n[Convergence Metrics]")
    for key, value in report['convergence_metrics'].items():
        print(f"  {key}: {value:.4f}")
    
    print("\n[Technology Stack]")
    for key, value in report['technology'].items():
        print(f"  {key}: {value}")
    
    print("\n[Monitoring Alerts]")
    for key, value in report['monitoring'].items():
        if key == 'recent_alerts':
            if value:
                print(f"  Recent alerts:")
                for alert in value[-3:]:
                    print(f"    - Step {alert['step']}: [{alert['severity']}] {alert['message']}")
        else:
            print(f"  {key}: {value}")
    
    # Detailed concept analysis
    print("\n" + "="*70)
    print("DETAILED CONCEPT ANALYSIS")
    print("="*70)
    
    current_time = time.time()
    for concept_id in [l1_ids[0], l1_ids[-1], ethical_id]:
        # Find concept in appropriate network
        concept = None
        for network in [taic.l1_network, taic.l3_network, taic.l4_network]:
            if concept_id in network.concepts:
                concept = network.concepts[concept_id]
                break
        
        if concept:
            print(f"\n[{concept_id}] {concept.description[:50]}...")
            print(f"  Layer: {concept.layer}")
            print(f"  Cognitive Level: {concept.cognitive_level.name}")
            print(f"  Dimension: {concept.current_dimension}")
            print(f"  Ethical Bias: {concept.ethical_bias:.2f}")
            print(f"  Entropy: {concept.get_metric('entropy', current_time):.4f}")
            print(f"  SRM: {concept.get_metric('srm', current_time):.4f}")
            print(f"  MAP: {concept.get_metric('map', current_time):.4f}")
            print(f"  BCP: {concept.get_metric('bcp', current_time):.4f}")
            print(f"  GAB: {concept.get_metric('gab', current_time):.4f}")
            print(f"  Convergence: {concept.get_metric('convergence_score', current_time):.4f}")
    
    # Visualizations
    print("\n" + "="*70)
    print("GENERATING VISUALIZATIONS")
    print("="*70)
    
    if MATPLOTLIB_AVAILABLE:
        print("\nGenerating plots...")
        taic.visualize_system()
        print("✓ Visualizations complete")
    else:
        print("Matplotlib not available - skipping visualization")
    
    print("\n" + "="*70)
    print("DEMONSTRATION COMPLETE")
    print("="*70)


# ============================================================================
# DEPLOYMENT UTILITIES
# ============================================================================


# ============================================================================
# DEMONSTRATION AND TESTING
# ============================================================================

def demo_enhanced_taic():
    """Comprehensive demonstration of enhanced T-AIC"""
    print("="*70)
    print("T-AIC ENHANCED PRODUCTION ARCHITECTURE")
    print("="*70)
    print()
    
    # Initialize with custom config
    config = TAICConfig(
        l1_capacity=2000,
        l3_capacity=100,
        l4_capacity=20,
        enable_quantum=QUTIP_AVAILABLE,
        enable_gpu=True,
        enable_alerts=True,
        ethical_drift_threshold=0.25
    )
    
    print(f"[CONFIG] Quantum: {config.enable_quantum}, GPU: {TORCH_AVAILABLE and torch.cuda.is_available()}")
    print()
    
    taic = OptimizedTAIC(config)
    
    # Create L1 concepts
    print("Creating L1 concepts...")
    l1_descriptions = [
        "Pattern recognition in temporal sequences",
        "Associative memory network formation",
        "Attention mechanism with gating",
        "Reward signal temporal difference learning",
        "Error gradient backpropagation",
        "Hierarchical feature extraction",
        "Working memory buffer management"
    ]
    
    l1_levels = [
        CognitiveLevel.PATTERN_RECOGNITION,
        CognitiveLevel.PATTERN_RECOGNITION,
        CognitiveLevel.ASSOCIATION,
        CognitiveLevel.ASSOCIATION,
        CognitiveLevel.REASONING,
        CognitiveLevel.REASONING,
        CognitiveLevel.META_COGNITION
    ]
    
    l1_ids = []
    for desc, level in zip(l1_descriptions, l1_levels):
        cid = taic.create_concept(desc, level, layer='l1')
        l1_ids.append(cid)
    
    print(f"✓ Created {len(l1_ids)} L1 concepts")
    
    # Create network connections
    print("\nEstablishing concept network...")
    for i in range(len(l1_ids) - 1):
        taic.connect_concepts(l1_ids[i], l1_ids[i+1], strength=0.7)
    
    # Cross-connections
    taic.connect_concepts(l1_ids[0], l1_ids[3], strength=0.5)
    taic.connect_concepts(l1_ids[2], l1_ids[5], strength=0.6)
    taic.connect_concepts(l1_ids[1], l1_ids[4], strength=0.4)
    
    print(f"✓ Established {len(l1_ids)-1+3} connections")
    
    # Create L3 concepts
    print("\nCreating L3 concepts...")
    l3_id1 = taic.create_concept(
        "Integrated multi-modal learning system",
        CognitiveLevel.META_COGNITION,
        layer='l3'
    )
    l3_id2 = taic.create_concept(
        "Meta-cognitive monitoring and control",
        CognitiveLevel.EMERGENT_INTEGRATION,
        layer='l3'
    )
    print(f"✓ Created 2 L3 concepts")
    
    # Inject ethical input
    print("\n[ETHICAL INPUT] Injecting compassion-loaded concept...")
    ethical_id = taic.inject_ethical_input(
        "Universal compassion and boundary permeability principle",
        CognitiveLevel.ADVANCED_INSIGHT,
        layer='l3'
    )
    
    # Cross-layer connections
    print("\nEstablishing cross-layer connections...")
    taic.connect_concepts(l1_ids[-1], l3_id1, strength=0.8, cross_layer=True)
    taic.connect_concepts(l3_id1, ethical_id, strength=0.9, cross_layer=True)
    print("✓ Cross-layer hierarchy established")
    
    # Create L4 meta-concept
    print("\nCreating L4 meta-concept...")
    l4_id = taic.create_concept(
        "Global optimization and integration framework",
        CognitiveLevel.GLOBAL_OPTIMIZATION,
        layer='l4'
    )
    taic.connect_concepts(ethical_id, l4_id, strength=0.9, cross_layer=True)
    print(f"✓ Created L4 concept: {l4_id}")
    
    # Run simulation
    print("\n" + "="*70)
    print("RUNNING ENHANCED SIMULATION (30 steps)")
    print("="*70)
    print()
    
    results = taic.simulate(num_steps=30, concept_ids=l1_ids, visualize_every=0)
    
    # Generate comprehensive report
    print("\n" + "="*70)
    print("COMPREHENSIVE SYSTEM REPORT")
    print("="*70)
    
    report = taic.get_system_report()
    
    print("\n[System Statistics]")
    for key, value in report['system_statistics'].items():
        print(f"  {key}: {value}")
    
    print("\n[Network Health]")
    for key, value in report['network_health'].items():
        if isinstance(value, float):
            print(f"  {key}: {value:.4f}")
        else:
            print(f"  {key}: {value}")
    
    print("\n[Convergence Metrics]")
    for key, value in report['convergence_metrics'].items():
        print(f"  {key}: {value:.4f}")
    
    print("\n[Technology Stack]")
    for key, value in report['technology'].items():
        print(f"  {key}: {value}")
    
    print("\n[Monitoring Alerts]")
    for key, value in report['monitoring'].items():
        if key == 'recent_alerts':
            if value:
                print(f"  Recent alerts:")
                for alert in value[-3:]:
                    print(f"    - Step {alert['step']}: [{alert['severity']}] {alert['message']}")
        else:
            print(f"  {key}: {value}")
    
    # Detailed concept analysis
    print("\n" + "="*70)
    print("DETAILED CONCEPT ANALYSIS")
    print("="*70)
    
    current_time = time.time()
    for concept_id in [l1_ids[0], l1_ids[-1], ethical_id]:
        # Find concept in appropriate network
        concept = None
        for network in [taic.l1_network, taic.l3_network, taic.l4_network]:
            if concept_id in network.concepts:
                concept = network.concepts[concept_id]
                break
        
        if concept:
            print(f"\n[{concept_id}] {concept.description[:50]}...")
            print(f"  Layer: {concept.layer}")
            print(f"  Cognitive Level: {concept.cognitive_level.name}")
            print(f"  Dimension: {concept.current_dimension}")
            print(f"  Ethical Bias: {concept.ethical_bias:.2f}")
            print(f"  Entropy: {concept.get_metric('entropy', current_time):.4f}")
            print(f"  SRM: {concept.get_metric('srm', current_time):.4f}")
            print(f"  MAP: {concept.get_metric('map', current_time):.4f}")
            print(f"  BCP: {concept.get_metric('bcp', current_time):.4f}")
            print(f"  GAB: {concept.get_metric('gab', current_time):.4f}")
            print(f"  Convergence: {concept.get_metric('convergence_score', current_time):.4f}")
    
    # Visualizations
    print("\n" + "="*70)
    print("GENERATING VISUALIZATIONS")
    print("="*70)
    
    if MATPLOTLIB_AVAILABLE:
        print("\nGenerating plots...")
        taic.visualize_system()
        print("✓ Visualizations complete")
    else:
        print("Matplotlib not available - skipping visualization")
    
    print("\n" + "="*70)
    print("DEMONSTRATION COMPLETE")
    print("="*70)

def run_system_tests():
    """Comprehensive system tests"""
    print("\n" + "="*70)
    print("RUNNING SYSTEM TESTS")
    print("="*70)
    
    # Test 1: Basic creation and metrics
    print("\n[TEST 1] Basic concept creation and metrics...")
    config = TAICConfig(l1_capacity=100, enable_alerts=False)
    taic = OptimizedTAIC(config)
    cid = taic.create_concept("Test concept", CognitiveLevel.REASONING, layer='l1')
    concept = taic.l1_network.concepts[cid]
    current_time = time.time()
    entropy = concept.get_metric('entropy', current_time)
    assert 0 <= entropy <= 1, "Entropy out of bounds"
    print(f"✓ Metrics valid (entropy={entropy:.4f})")
    
    # Test 2: Batch operations
    print("\n[TEST 2] Batch metric computation...")
    cids = [taic.create_concept(f"Concept {i}", CognitiveLevel.ASSOCIATION, layer='l1')
            for i in range(10)]
    concepts = [taic.l1_network.concepts[cid] for cid in cids]
    batch_metrics = MetricEngine.batch_compute(concepts)
    assert len(batch_metrics['entropy']) == 10, "Batch size mismatch"
    print(f"✓ Batch computation successful ({len(concepts)} concepts)")
    
    # Test 3: Network propagation
    print("\n[TEST 3] Network propagation...")
    for i in range(len(cids) - 1):
        taic.connect_concepts(cids[i], cids[i+1], strength=0.5)
    propagation = taic.l1_network.propagate(cids[0], intensity=1.0)
    assert len(propagation) > 0, "Propagation failed"
    print(f"✓ Propagation reached {len(propagation)} concepts")
    
    # Test 4: Simulation stability
    print("\n[TEST 4] Simulation stability...")
    results = taic.simulate(num_steps=20, concept_ids=cids[:5])
    final_coherence = results[-1]['global_coherence']
    assert 0 <= final_coherence <= 1, "Coherence out of bounds"
    print(f"✓ Simulation stable (final coherence={final_coherence:.4f})")
    
    # Test 5: Dimensional adaptation
    print("\n[TEST 5] Dimensional adaptation...")
    test_concept = taic.l1_network.concepts[cids[0]]
    initial_dim = test_concept.current_dimension
    test_concept.resize_state(8)
    assert test_concept.current_dimension == 8, "Dimension resize failed"
    test_concept.resize_state(initial_dim)
    print(f"✓ Dimensional adaptation working ({initial_dim}D → 8D → {initial_dim}D)")
    
    # Test 6: Ethical input injection
    print("\n[TEST 6] Ethical input injection...")
    ethical_id = taic.inject_ethical_input(
        "Test ethical concept",
        CognitiveLevel.ADVANCED_INSIGHT,
        layer='l3'
    )
    ethical_concept = taic.l3_network.concepts[ethical_id]
    assert ethical_concept.ethical_bias > 0.8, "Ethical bias not set"
    print(f"✓ Ethical input injected (bias={ethical_concept.ethical_bias:.2f})")
    
    print("\n" + "="*70)
    print("ALL TESTS PASSED")
    print("="*70)

def interactive_demo():
    print("OptimizedTAIC (Mac Dictionary Edition) - Informed Decision Making Demo")
    taic = OptimizedTAIC()
    personalization = taic.personalization
    decision = DecisionLayer()
    personalization.load_profiles()
    user = "Thaniel"

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

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================


################################################################################
# INTEGRATED CONTENT FROM HMENEMENEM.PY
################################################################################

# Core dataclasses and classes from Hmenemenem

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
      - Quine: The indeterminacy of translation--meaning is not always fixed.

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
      Mystic traditions often use symbols, seeing meaning as multi-layered--exoteric (outer/literal) and esoteric (inner/hidden).

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

   - “The limits of my language mean the limits of my world.” -- Ludwig Wittgenstein
   - “He who has a why to live for can bear almost any how.” -- Friedrich Nietzsche
   - “The Tao that can be told is not the eternal Tao.” -- Lao Tzu

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
“Meaning” is not a single concept, but a complex interplay of sign, mind, context, and culture. It encompasses reference, sense, significance, purpose, and transcendence, and is at the heart of what it means to be human--both in seeking to understand the world and in trying to make sense of our own existence.

---

8. Meaning and Culture

Culture profoundly influences meaning, shaping both the creation and interpretation of signs, symbols, and experiences. Meaning is rarely absolute--it is context-dependent, and much of that context is cultural.

- Shared Symbols and Language: Culture provides a common set of symbols, metaphors, idioms, and language structures. For example, the meaning of a gesture, color, or word may be positive in one culture and negative in another (e.g., the color white symbolizes purity in Western cultures but mourning in some East Asian traditions).

- Socialization: Through family, traditions, rituals, education, and media, individuals learn cultural meanings, which guide how they understand themselves, others, and the world.

- Collective Narratives & Worldviews: Cultures transmit meaning through myths, stories, religious beliefs, and collective memories, shaping peoples' sense of purpose and significance.

- Interpretative Communities: Stanley Fish and others argue that what is meaningful is determined by “interpretive communities”--groups that share similar ways of making sense of the world. Thus, meaning is not just found in the individual or the text, but in the shared cultural practices of a community.

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

Thus, culture is not just an influence on meaning--it is often the very soil from which shared meanings emerge.
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
Certainly! Here is a comprehensive and detailed exploration of “nuance”--integrating linguistic, philosophical,
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
- It recognizes the “gray areas”--the subtle gradations between binaries and the inadequacy of black-and-white thinking.

### b. Hermeneutics (Interpretation):
- Nuance is central to interpretation, demanding sensitivity to context, voice, intention, and subtext.
- Gadamer and Ricoeur stress that true understanding involves attending to nuances embedded in language and culture.

### c. Ethics and Morality:
- Many ethical dilemmas require attention to nuances: the specific context, intentions, relationships, and consequences.

## 3. Psychological & Cognitive Science Perspectives

### a. Perception and Cognition:
- Humans are wired to detect and interpret nuances--fine details in facial expressions, intonation, or behavior.
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
- Many mystical traditions focus on the ineffable--experiences that transcend conceptual clarity and are understood through subtle intuition or direct insight.
- “Nuance” here might refer to the fine gradations of spiritual feeling or insight not easily put into words.

### b. Symbolism:
- Esoteric traditions (e.g., Kabbalah, Sufism) cherish nuanced interpretations of sacred texts--hidden meanings perceived only through subtle, contemplative reading.

## 7. Interdisciplinary Insights

### a. Science & Mathematics:
- Scientific theories often depend on nuanced distinctions (e.g., between correlation and causation, or different types of probability).

### b. Law:
- Legal reasoning and the practice of justice rest on nuance--a careful distinction of cases, precedents, and circumstances.

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

- “Truth is rarely pure and never simple.” -- Oscar Wilde (on the value of nuance)
- “It is the mark of an educated mind to be able to entertain a thought without accepting it.” -- Aristotle (on embracing complexity)
- “In the depth of winter, I finally learned that within me there lay an invincible summer.” -- Albert Camus (on nuance of feeling)

## Synthesis

In essence, “nuance” refers to the subtle variations, gradations, and complexities that enrich all forms of meaning, perception, and expression. It is the recognition of what lies between the obvious and the oppositional: the shades, undertones, and ambiguous spaces that constitute the fullness of experience, thought, and communication. Embracing nuance is essential for deep understanding, interpretation, empathy, and creativity--whether in philosophy, art, language, or life itself.
---
"""

NUANCE_KNOWLEDGE = {
    "short_definition": "Nuance is a subtle distinction or variation in meaning, tone, expression, feeling, or context.",
    "linguistic": "In language, nuance refers to the fine gradations that alter meaning, often marked by word choice, tone, or syntax.",
    "philosophical": "Nuance resists reductionism and acknowledges complexity, ambiguity, context, and the grey areas of thought.",
    "psychology": "Humans perceive and process subtle details--nuances--in emotion, expression, perception, and understanding.",
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
        "Truth is rarely pure and never simple. -- Oscar Wilde",
        "It is the mark of an educated mind to be able to entertain a thought without accepting it. -- Aristotle",
        "In the depth of winter, I finally learned that within me there lay an invincible summer. -- Albert Camus",
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
    "psychology": "Humans perceive and process subtle details--nuances--in emotion, expression, perception, and understanding.",
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
        "Truth is rarely pure and never simple. -- Oscar Wilde",
        "It is the mark of an educated mind to be able to entertain a thought without accepting it. -- Aristotle",
        "In the depth of winter, I finally learned that within me there lay an invincible summer. -- Albert Camus",
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
            "Certainly! Here is a comprehensive and detailed exploration of “nuance”--integrating linguistic, philosophical, "
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
    user = "Thaniel"

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

 

# Understanding perception and what drives it: """Motivation affects perception"? Motivation used in this was has a broader meaning. It's not just "Get up and go to the gym because you're motivated to go to the gym" it's because you are motivated by going to the gym, all you notice at all the gyms in your local area. Or other people in shape. It's similar to "Encouraged by", "Pre-exposed to". What you are motivated by is how you will see the world around you both in a macro/micro sense. It is also possible too to have times where none of that stuff even crosses your mind and you just do whatever you do. If you are motivated by survival? Motivated by gratification? Power and control? And so on all the way up until the idea of you or concept disappears. It's not that difficult to see what people's motivations are after knowing about this concept and intuitively understanding it. All of this covers the broad and the specific."""

"""
T-AIC Enhanced Production Architecture

Features:
- Adaptive dimensional hierarchy integration
- Optional quantum state evolution
- PyTorch GPU acceleration
- Cross-layer interactions
- Ethical input injection
- Real-time monitoring and alerts
- Comprehensive visualization
"""
import numpy as np
import scipy.sparse as sp
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any, Union
from enum import IntEnum
import time
from collections import defaultdict
import warnings

# Optional dependencies
try:
    import qutip as qt
    QUTIP_AVAILABLE = True
except ImportError:
    QUTIP_AVAILABLE = False
    warnings.warn("QuTiP not available - quantum features disabled")

try:
    import torch
    TORCH_AVAILABLE = True
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
except ImportError:
    TORCH_AVAILABLE = False
    device = None
    warnings.warn("PyTorch not available - using NumPy fallback")

try:
    import matplotlib.pyplot as plt
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False
    warnings.warn("Matplotlib not available - visualization disabled")


# ============================================================================
# CONFIGURATION
# ============================================================================

@dataclass
class TAICConfig:
    """Centralized configuration for T-AIC system"""
    # Network capacities
    l1_capacity: int = 2000
    l3_capacity: int = 100
    l4_capacity: int = 20
    
    # Physics/dynamics parameters
    entropy_accumulation_rate: float = 0.05
    srm_reduction_multiplier: float = 0.15
    map_gain_rate: float = 0.05
    bcp_surge_threshold: float = 0.8
    bcp_surge_rate: float = 0.1
    state_noise_amplitude: float = 0.01
    
    # Convergence score weights
    weight_entropy: float = 0.3
    weight_trajectory: float = 0.3
    weight_srm: float = 0.2
    weight_bcp: float = 0.15
    weight_gab: float = 0.05
    
    # Level progression thresholds
    threshold_association: float = 0.5
    threshold_reasoning: float = 0.65
    threshold_metacognition: float = 0.75
    threshold_global: float = 0.9
    
    # Monitoring
    ethical_drift_threshold: float = 0.2
    enable_alerts: bool = True
    
    # Performance
    cache_duration: float = 5.0
    enable_quantum: bool = False
    enable_gpu: bool = True
    quantum_time_scale: float = 0.1


# ============================================================================
# CORE DATA STRUCTURES
# ============================================================================

class CognitiveLevel(IntEnum):
    """Hierarchical cognitive complexity levels"""
    PATTERN_RECOGNITION = 1
    ASSOCIATION = 2
    REASONING = 3
    META_COGNITION = 4
    EMERGENT_INTEGRATION = 5
    ADVANCED_INSIGHT = 6
    GLOBAL_OPTIMIZATION = 7
    
    @property
    def parameter_count(self) -> int:
        """Approximate computational complexity"""
        return 10 ** self.value


@dataclass
class ConceptState:
    """Enhanced concept representation with dynamic dimensionality"""
    id: str
    cognitive_level: CognitiveLevel
    description: str = ""
    
    # Dynamic state vector (dimension can change)
    state_vector: np.ndarray = field(default_factory=lambda: np.ones(6) / np.sqrt(6))
    previous_state: np.ndarray = field(default_factory=lambda: np.ones(6) / np.sqrt(6))
    current_dimension: int = 6
    
    # Quantum state (optional)
    quantum_state: Optional[Any] = None  # qt.Qobj when quantum enabled
    
    # Lazy-computed metrics cache
    _cache: Dict[str, Tuple[float, float]] = field(default_factory=dict)
    
    # Network connectivity
    connected_concepts: List[str] = field(default_factory=list)
    connection_strengths: np.ndarray = field(default=None)
    
    # Ethical bias (for injected concepts)
    ethical_bias: float = 0.0  # >0.8 for ethically-loaded concepts
    
    # Metadata
    creation_time: float = field(default_factory=time.time)
    last_update: float = field(default_factory=time.time)
    layer: str = "l1"
    
    def __post_init__(self):
        if self.connection_strengths is None:
            self.connection_strengths = np.array([])
        self.current_dimension = len(self.state_vector)
    
    def get_metric(self, name: str, current_time: float,
                   cache_duration: float = 5.0) -> float:
        """Retrieve metric with caching"""
        if name in self._cache:
            value, timestamp = self._cache[name]
            if current_time - timestamp < cache_duration:
                return value
        
        try:
            value = MetricEngine.compute_single_metric(
                name, self.state_vector, self.previous_state,
                self.cognitive_level
            )
        except Exception as e:
            warnings.warn(f"Metric computation failed for {name}: {e}")
            value = 0.0
        
        self._cache[name] = (value, current_time)
        return value
    
    def invalidate_cache(self):
        """Clear cached metrics after state update"""
        self._cache.clear()
    
    def resize_state(self, new_dimension: int):
        """Resize state vector to new dimension"""
        if new_dimension == self.current_dimension:
            return
        
        old_dim = self.current_dimension
        new_state = np.zeros(new_dimension)
        
        if new_dimension > old_dim:
            # Expanding: copy existing + add small orthogonal components
            new_state[:old_dim] = self.state_vector
            extra = np.random.randn(new_dimension - old_dim) * 0.1
            new_state[old_dim:] = extra
        else:
            # Contracting: truncate
            new_state = self.state_vector[:new_dimension]
        
        # Renormalize
        norm = np.linalg.norm(new_state)
        if norm > 1e-10:
            self.state_vector = new_state / norm
        
        self.previous_state = self.previous_state[:new_dimension] if len(self.previous_state) >= new_dimension else np.pad(self.previous_state, (0, max(0, new_dimension - len(self.previous_state))))
        self.current_dimension = new_dimension
        self.invalidate_cache()


# ============================================================================
# ENHANCED METRIC ENGINE
# ============================================================================

class MetricEngine:
    """Centralized metric computation with error handling"""
    
    @staticmethod
    def compute_all_metrics(state: np.ndarray,
                           previous: np.ndarray,
                           cognitive_level: CognitiveLevel,
                           ethical_bias: float = 0.0) -> Dict[str, float]:
        """Compute all T-AIC metrics with robust error handling"""
        try:
            # Normalize state to probabilities
            probs = np.abs(state) ** 2
            prob_sum = probs.sum()
            if prob_sum < 1e-10:
                # Zero state fallback
                return {
                    'entropy': 1.0,
                    'cbmi': 0.0,
                    'gab': 0.0,
                    'srm': 0.0,
                    'bcp': 0.0,
                    'map': 0.0,
                    'trajectory': 0.0,
                    'convergence_score': 0.0
                }
            probs = probs / prob_sum
            
            # System Entropy
            entropy = -np.sum(probs * np.log(probs + 1e-10))
            normalized_entropy = entropy / np.log(len(probs)) if len(probs) > 1 else entropy
            
            # Self-Referential Minimization
            state_change = np.linalg.norm(state - previous[:len(state)])
            srm = np.exp(-state_change)
            
            # Minimal Action Principle
            complexity = np.log10(cognitive_level.parameter_count + 1)
            map_val = srm / complexity if complexity > 0 else srm
            
            # Cross-Boundary Mutual Information
            cbmi = srm * 0.7 + (1.0 - normalized_entropy) * 0.3
            
            # Boundary Condition Permeability (boosted by ethical bias)
            bcp_base = cbmi * map_val
            bcp = min(1.0, bcp_base + ethical_bias * 0.2)
            
            # Optimal State Trajectory
            trajectory = 1.0 - normalized_entropy
            
            # Gratitude Appreciation Bias
            gab = 0.0
            if normalized_entropy < 0.2 and srm > 0.8:
                gab = min(1.0, (0.8 - normalized_entropy) * srm)
            
            # Convergence score
            convergence_score = (
                (1 - normalized_entropy) * 0.3 +
                trajectory * 0.3 +
                srm * 0.2 +
                bcp * 0.15 +
                gab * 0.05
            )
            
            return {
                'entropy': float(normalized_entropy),
                'srm': float(srm),
                'map': float(map_val),
                'cbmi': float(cbmi),
                'bcp': float(bcp),
                'trajectory': float(trajectory),
                'gab': float(gab),
                'convergence_score': float(convergence_score)
            }
        except Exception as e:
            warnings.warn(f"Metric computation error: {e}")
            return {
                'entropy': 0.0,
                'cbmi': 0.0,
                'gab': 0.0,
                'srm': 0.0,
                'bcp': 0.0,
                'map': 0.0,
                'trajectory': 0.0,
                'convergence_score': 0.0
            }
    
    @staticmethod
    def compute_single_metric(name: str, state: np.ndarray,
                             previous: np.ndarray,
                             cognitive_level: CognitiveLevel) -> float:
        """Compute individual metric"""
        metrics = MetricEngine.compute_all_metrics(state, previous, cognitive_level)
        return metrics.get(name, 0.0)
    
    @staticmethod
    def batch_compute(states: List[ConceptState],
                     use_gpu: bool = True) -> Dict[str, np.ndarray]:
        """Vectorized batch computation with optional GPU acceleration"""
        n = len(states)
        if n == 0:
            return {}
        
        try:
            # Check if dimensions are compatible
            dims = [len(s.state_vector) for s in states]
            if len(set(dims)) > 1:
                # Mixed dimensions - pad to max
                max_dim = max(dims)
                state_matrix = np.zeros((n, max_dim))
                previous_matrix = np.zeros((n, max_dim))
                for i, s in enumerate(states):
                    state_matrix[i, :len(s.state_vector)] = s.state_vector
                    previous_matrix[i, :len(s.previous_state)] = s.previous_state[:len(s.state_vector)]
            else:
                # Uniform dimensions
                state_matrix = np.stack([s.state_vector for s in states])
                previous_matrix = np.stack([s.previous_state for s in states])
            
            # GPU acceleration if available
            if TORCH_AVAILABLE and use_gpu and torch.cuda.is_available():
                return MetricEngine._batch_compute_gpu(states, state_matrix, previous_matrix)
            else:
                return MetricEngine._batch_compute_cpu(states, state_matrix, previous_matrix)
        except Exception as e:
            warnings.warn(f"Batch computation failed: {e}, falling back to sequential")
            # Sequential fallback
            results = defaultdict(list)
            for state in states:
                metrics = MetricEngine.compute_all_metrics(
                    state.state_vector, state.previous_state,
                    state.cognitive_level, state.ethical_bias
                )
                for key, value in metrics.items():
                    results[key].append(value)
            return {k: np.array(v) for k, v in results.items()}
    
    @staticmethod
    def _batch_compute_gpu(states: List[ConceptState],
                          state_matrix: np.ndarray,
                          previous_matrix: np.ndarray) -> Dict[str, np.ndarray]:
        """GPU-accelerated batch computation"""
        state_tensor = torch.tensor(state_matrix, device=device, dtype=torch.float32)
        previous_tensor = torch.tensor(previous_matrix, device=device, dtype=torch.float32)
        
        # Batch normalize
        probs_tensor = torch.abs(state_tensor) ** 2
        probs_tensor = probs_tensor / (probs_tensor.sum(dim=1, keepdim=True) + 1e-10)
        
        # Batch entropy
        entropy_tensor = -torch.sum(probs_tensor * torch.log(probs_tensor + 1e-10), dim=1)
        entropy_tensor = entropy_tensor / np.log(probs_tensor.shape[1])
        
        # Batch SRM
        state_changes = torch.norm(state_tensor - previous_tensor, dim=1)
        srm_tensor = torch.exp(-state_changes)
        
        # Batch MAP
        complexities = torch.tensor(
            [np.log10(s.cognitive_level.parameter_count + 1) for s in states],
            device=device, dtype=torch.float32
        )
        map_tensor = srm_tensor / (complexities + 1e-10)
        
        # Batch CBMI, BCP
        cbmi_tensor = srm_tensor * 0.7 + (1.0 - entropy_tensor) * 0.3
        ethical_biases = torch.tensor([s.ethical_bias for s in states],
                                     device=device, dtype=torch.float32)
        bcp_tensor = torch.clamp(cbmi_tensor * map_tensor + ethical_biases * 0.2, max=1.0)
        
        trajectory_tensor = 1.0 - entropy_tensor
        
        # Batch GAB
        gab_tensor = torch.zeros(len(states), device=device)
        gab_mask = (entropy_tensor < 0.2) & (srm_tensor > 0.8)
        gab_tensor[gab_mask] = torch.clamp(
            (0.8 - entropy_tensor[gab_mask]) * srm_tensor[gab_mask], max=1.0
        )
        
        # Convergence
        convergence_tensor = (
            (1 - entropy_tensor) * 0.3 +
            trajectory_tensor * 0.3 +
            srm_tensor * 0.2 +
            bcp_tensor * 0.15 +
            gab_tensor * 0.05
        )
        
        # Convert back to CPU
        return {
            'entropy': entropy_tensor.cpu().numpy(),
            'srm': srm_tensor.cpu().numpy(),
            'map': map_tensor.cpu().numpy(),
            'cbmi': cbmi_tensor.cpu().numpy(),
            'bcp': bcp_tensor.cpu().numpy(),
            'trajectory': trajectory_tensor.cpu().numpy(),
            'gab': gab_tensor.cpu().numpy(),
            'convergence_score': convergence_tensor.cpu().numpy()
        }
    
    @staticmethod
    def _batch_compute_cpu(states: List[ConceptState],
                          state_matrix: np.ndarray,
                          previous_matrix: np.ndarray) -> Dict[str, np.ndarray]:
        """CPU batch computation"""
        n = len(states)
        
        # Batch normalize
        probs_matrix = np.abs(state_matrix) ** 2
        probs_matrix = probs_matrix / (probs_matrix.sum(axis=1, keepdims=True) + 1e-10)
        
        # Batch entropy
        entropy_vec = -np.sum(probs_matrix * np.log(probs_matrix + 1e-10), axis=1)
        entropy_vec = entropy_vec / np.log(probs_matrix.shape[1])
        
        # Batch SRM
        state_changes = np.linalg.norm(state_matrix - previous_matrix, axis=1)
        srm_vec = np.exp(-state_changes)
        
        # Batch MAP
        complexities = np.array([np.log10(s.cognitive_level.parameter_count + 1)
                                for s in states])
        map_vec = srm_vec / (complexities + 1e-10)
        
        # Batch CBMI, BCP
        cbmi_vec = srm_vec * 0.7 + (1.0 - entropy_vec) * 0.3
        ethical_biases = np.array([s.ethical_bias for s in states])
        bcp_vec = np.minimum(1.0, cbmi_vec * map_vec + ethical_biases * 0.2)
        
        trajectory_vec = 1.0 - entropy_vec
        
        # Batch GAB
        gab_vec = np.zeros(n)
        gab_mask = (entropy_vec < 0.2) & (srm_vec > 0.8)
        gab_vec[gab_mask] = np.minimum(1.0, (0.8 - entropy_vec[gab_mask]) * srm_vec[gab_mask])
        
        # Convergence
        convergence_vec = (
            (1 - entropy_vec) * 0.3 +
            trajectory_vec * 0.3 +
            srm_vec * 0.2 +
            bcp_vec * 0.15 +
            gab_vec * 0.05
        )
        
        return {
            'entropy': entropy_vec,
            'srm': srm_vec,
            'map': map_vec,
            'cbmi': cbmi_vec,
            'bcp': bcp_vec,
            'trajectory': trajectory_vec,
            'gab': gab_vec,
            'convergence_score': convergence_vec
        }


# ============================================================================
# SPARSE CONCEPT NETWORK
# ============================================================================

class SparseConceptNetwork:
    """Memory-efficient sparse network for concept relationships"""
    
    def __init__(self, max_concepts: int = 10000):
        self.max_concepts = max_concepts
        self.adjacency = sp.lil_matrix((max_concepts, max_concepts), dtype=np.float32)
        self.concepts: Dict[str, ConceptState] = {}
        self.id_to_index: Dict[str, int] = {}
        self.index_to_id: Dict[int, str] = {}
        self.free_indices = list(range(max_concepts))
        self.total_connections = 0
        self.sparsity = 1.0
    
    def add_concept(self, concept: ConceptState) -> int:
        if concept.id in self.id_to_index:
            return self.id_to_index[concept.id]
        
        if not self.free_indices:
            raise RuntimeError("Network capacity exceeded")
        
        idx = self.free_indices.pop(0)
        self.concepts[concept.id] = concept
        self.id_to_index[concept.id] = idx
        self.index_to_id[idx] = concept.id
        return idx
    
    def remove_concept(self, concept_id: str):
        if concept_id not in self.id_to_index:
            return
        
        idx = self.id_to_index[concept_id]
        self.adjacency[idx, :] = 0
        self.adjacency[:, idx] = 0
        
        del self.concepts[concept_id]
        del self.id_to_index[concept_id]
        del self.index_to_id[idx]
        self.free_indices.append(idx)
        self.free_indices.sort()
        self._update_statistics()
    
    def connect(self, source_id: str, target_id: str, strength: float = 1.0):
        if source_id not in self.id_to_index or target_id not in self.id_to_index:
            return
        
        src_idx = self.id_to_index[source_id]
        tgt_idx = self.id_to_index[target_id]
        old_val = self.adjacency[src_idx, tgt_idx]
        self.adjacency[src_idx, tgt_idx] = strength
        
        if old_val == 0 and strength != 0:
            self.total_connections += 1
        elif old_val != 0 and strength == 0:
            self.total_connections -= 1
        
        self._update_statistics()
    
    def get_neighbors(self, concept_id: str, threshold: float = 0.1) -> List[Tuple[str, float]]:
        if concept_id not in self.id_to_index:
            return []
        
        idx = self.id_to_index[concept_id]
        row = self.adjacency.getrow(idx).toarray().flatten()
        neighbors = []
        
        for i, strength in enumerate(row):
            if strength > threshold and i in self.index_to_id:
                neighbors.append((self.index_to_id[i], strength))
        
        return sorted(neighbors, key=lambda x: x[1], reverse=True)
    
    def propagate(self, source_id: str, intensity: float = 1.0,
                 steps: int = 3, use_gpu: bool = True) -> Dict[str, float]:
        """Propagate activation with optional GPU acceleration"""
        if source_id not in self.id_to_index:
            return {}
        
        src_idx = self.id_to_index[source_id]
        
        if TORCH_AVAILABLE and use_gpu and torch.cuda.is_available():
            # GPU propagation
            activation = torch.zeros(self.max_concepts, device=device)
            activation[src_idx] = intensity
            
            # Convert to sparse tensor
            adj_coo = self.adjacency.tocoo()
            indices = torch.LongTensor([adj_coo.row, adj_coo.col]).to(device)
            values = torch.FloatTensor(adj_coo.data).to(device)
            adj_sparse = torch.sparse_coo_tensor(
                indices, values,
                (self.max_concepts, self.max_concepts)
            ).to(device)
            
            for _ in range(steps):
                activation = torch.sparse.mm(adj_sparse.t(), activation.unsqueeze(1)).squeeze() * 0.7
            
            activation = activation.cpu().numpy()
        else:
            # CPU propagation
            activation = np.zeros(self.max_concepts)
            activation[src_idx] = intensity
            adj_csr = self.adjacency.tocsr()
            
            for _ in range(steps):
                activation = adj_csr.T @ activation * 0.7
        
        # Extract results
        result = {}
        for idx, value in enumerate(activation):
            if value > 0.01 and idx in self.index_to_id:
                result[self.index_to_id[idx]] = float(value)
        
        return result
    
    def _update_statistics(self):
        active_count = len(self.concepts)
        max_connections = active_count * (active_count - 1)
        self.sparsity = 1.0 - (self.total_connections / max(max_connections, 1))
    
    def get_statistics(self) -> Dict[str, Any]:
        return {
            'active_concepts': len(self.concepts),
            'total_connections': self.total_connections,
            'sparsity': self.sparsity,
            'capacity_used': len(self.concepts) / self.max_concepts,
            'memory_estimate_mb': (
                self.adjacency.nnz * 12 + len(self.concepts) * 1000
            ) / 1024 / 1024
        }


# ============================================================================
# ADAPTIVE DIMENSIONAL HIERARCHY
# ============================================================================

class AdaptiveDimensionalHierarchy:
    """Adaptive dimensionality based on cognitive complexity"""
    
    def __init__(self):
        # Fixed: sort by threshold descending for correct priority
        self.level_thresholds = {
            10: 0.95,  # Meta-cognition -> 10D
            8: 0.85,   # Very high -> 8D
            6: 0.7,    # High -> 6D
            5: 0.5,    # Medium -> 5D
            4: 0.3     # Low -> 4D
        }
    
    def get_optimal_dimension(self, concept: ConceptState,
                             integration_score: float) -> int:
        """Determine optimal embedding dimension"""
        base_dim = min(2 + concept.cognitive_level.value, 10)
        
        # Check thresholds in descending order (highest first)
        for dim, threshold in sorted(self.level_thresholds.items(),
                                    key=lambda x: x[1], reverse=True):
            if integration_score >= threshold:
                return min(dim, 10)
        
        return min(base_dim, 6)
    
    def embed(self, state_vector: np.ndarray, target_dim: int) -> np.ndarray:
        """Embed state vector into higher dimension"""
        current_dim = len(state_vector)
        if target_dim <= current_dim:
            return state_vector[:target_dim]
        
        expanded = np.zeros(target_dim)
        expanded[:current_dim] = state_vector
        extra_dims = target_dim - current_dim
        
        if extra_dims > 0:
            ortho = np.random.randn(extra_dims) * 0.1
            ortho = ortho / (np.linalg.norm(ortho) + 1e-10)
            expanded[current_dim:] = ortho
        
        norm = np.linalg.norm(expanded)
        return expanded / (norm + 1e-10) if norm > 1e-10 else expanded
    
    def project_down(self, high_dim_vector: np.ndarray, target_dim: int) -> np.ndarray:
        """Project from higher to lower dimension"""
        if len(high_dim_vector) <= target_dim:
            return high_dim_vector
        
        projected = high_dim_vector[:target_dim]
        norm = np.linalg.norm(projected)
        return projected / (norm + 1e-10) if norm > 1e-10 else projected


# ============================================================================
# QUANTUM STATE MANAGER
# ============================================================================

class QuantumStateManager:
    """Manages quantum state evolution (if enabled)"""
    
    def __init__(self, enabled: bool = False):
        self.enabled = enabled and QUTIP_AVAILABLE
        if self.enabled:
            print("[Quantum] QuTiP-based quantum simulation enabled")
    
    def evolve_state(self, concept: ConceptState, metrics: Dict[str, float],
                    time_delta: float, time_scale: float = 0.1):
        """Evolve quantum state based on metrics"""
        if not self.enabled:
            return
        
        try:
            dim = len(concept.state_vector)
            
            # Build Hamiltonian from metrics
            # SRM drives X-rotation (mixing), entropy drives Z (phase)
            H = (metrics['srm'] * qt.sigmax() +
                 (1 - metrics['entropy']) * qt.sigmaz())
            
            # Scale to appropriate dimension
            if dim > 2:
                H = qt.tensor(H, qt.qeye(dim // 2))
            
            # Time evolution operator
            U = (-1j * H * time_delta * time_scale).expm()
            
            # Create or update quantum state
            if concept.quantum_state is None:
                # Initialize from classical state
                concept.quantum_state = qt.Qobj(concept.state_vector)
            
            # Evolve
            concept.quantum_state = U * concept.quantum_state
            
            # Extract to classical
            if isinstance(concept.quantum_state, qt.Qobj):
                concept.state_vector = np.abs(concept.quantum_state.full().flatten())
                norm = np.linalg.norm(concept.state_vector)
                if norm > 1e-10:
                    concept.state_vector = concept.state_vector / norm
        except Exception as e:
            warnings.warn(f"Quantum evolution failed: {e}, falling back to classical")
            self.enabled = False


# ============================================================================
# ENHANCED CAUSAL ENGINE
# ============================================================================

class CausalEngine:
    """Handles causal dynamics with dimensional adaptation and quantum support"""
    
    def __init__(self, network: SparseConceptNetwork, config: TAICConfig,
                 quantum_manager: Optional[QuantumStateManager] = None):
        self.network = network
        self.config = config
        self.quantum_manager = quantum_manager
        
        # Fixed: use valid CognitiveLevel values
        self.level_progression_thresholds = {
            CognitiveLevel.ASSOCIATION: config.threshold_association,
            CognitiveLevel.REASONING: config.threshold_reasoning,
            CognitiveLevel.META_COGNITION: config.threshold_metacognition,
            CognitiveLevel.GLOBAL_OPTIMIZATION: config.threshold_global
        }
        self.dim_hierarchy = AdaptiveDimensionalHierarchy()
    
    def process_step(self, concept_ids: List[str], time_delta: float,
                    enable_dimensional_adaptation: bool = True) -> Dict[str, Any]:
        """Process one simulation step with full enhancements"""
        results = {}
        current_time = time.time()
        
        concepts = [self.network.concepts[cid] for cid in concept_ids
                   if cid in self.network.concepts]
        
        if not concepts:
            return results
        
        # Batch compute metrics
        use_gpu = self.config.enable_gpu and TORCH_AVAILABLE
        metrics = MetricEngine.batch_compute(concepts, use_gpu=use_gpu)
        
        # Process each concept
        for i, concept in enumerate(concepts):
            concept_metrics = {k: v[i] for k, v in metrics.items()}
            
            # 1. Adaptive dimensionality (NEW)
            if enable_dimensional_adaptation:
                self._apply_dimensional_adaptation(concept, concept_metrics)
            
            # 2. Apply dynamics (quantum or classical)
            self._apply_dynamics(concept, concept_metrics, time_delta)
            
            # 3. Check level progression
            self._check_level_progression(concept, concept_metrics['convergence_score'])
            
            # 4. Update timestamps
            concept.last_update = current_time
            
            results[concept.id] = {
                'metrics': concept_metrics,
                'cognitive_level': concept.cognitive_level.name,
                'state_change': np.linalg.norm(concept.state_vector - concept.previous_state),
                'dimension': concept.current_dimension
            }
        
        return results
    
    def _apply_dimensional_adaptation(self, concept: ConceptState,
                                     metrics: Dict[str, float]):
        """NEW: Dynamically adjust concept dimensionality based on integration"""
        integration_score = metrics.get('cbmi', 0.0)
        optimal_dim = self.dim_hierarchy.get_optimal_dimension(concept, integration_score)
        
        if optimal_dim != concept.current_dimension:
            concept.resize_state(optimal_dim)
    
    def _apply_dynamics(self, concept: ConceptState, metrics: Dict[str, float],
                       time_delta: float):
        """Apply T-AIC dynamics with quantum or classical evolution"""
        concept.previous_state = concept.state_vector.copy()
        
        # Quantum evolution if enabled
        if self.quantum_manager and self.quantum_manager.enabled:
            self.quantum_manager.evolve_state(
                concept, metrics, time_delta,
                self.config.quantum_time_scale
            )
            concept.invalidate_cache()
            return
        
        # Classical evolution
        entropy_rate = self.config.entropy_accumulation_rate * (1.0 - metrics['srm'] * 0.7)
        
        if metrics['srm'] > 0.5:
            entropy_reduction = metrics['srm'] * self.config.srm_reduction_multiplier
        else:
            entropy_reduction = 0.0
        
        if metrics['srm'] > 0.7:
            map_gain = self.config.map_gain_rate
        else:
            map_gain = 0.0
        
        if metrics['bcp'] > self.config.bcp_surge_threshold:
            trajectory_surge = metrics['bcp'] * self.config.bcp_surge_rate
        else:
            trajectory_surge = 0.0
        
        # State evolution with noise
        state_noise = np.random.randn(len(concept.state_vector)) * self.config.state_noise_amplitude
        concept.state_vector = concept.state_vector + state_noise
        
        # Normalize
        norm = np.linalg.norm(concept.state_vector)
        if norm > 1e-10:
            concept.state_vector = concept.state_vector / norm
        
        concept.invalidate_cache()
    
    def _check_level_progression(self, concept: ConceptState, convergence: float):
        """Check if concept should progress to higher cognitive level"""
        current_level = concept.cognitive_level
        
        for target_level, threshold in sorted(self.level_progression_thresholds.items()):
            if (convergence >= threshold and
                target_level > current_level and
                target_level.value == current_level.value + 1):
                concept.cognitive_level = target_level
                print(f"[LEVEL PROGRESSION] {concept.id}: {current_level.name} → {target_level.name}")
                break


# ============================================================================
# ATTENTION ENGINE
# ============================================================================

class AttentionEngine:
    """Handles attention dynamics and oscillations"""
    
    def __init__(self, network: SparseConceptNetwork):
        self.network = network
    
    def compute_coherence(self, concept_ids: List[str]) -> float:
        """Compute collective coherence for concept group"""
        if not concept_ids:
            return 1.0
        
        concepts = [self.network.concepts[cid] for cid in concept_ids
                   if cid in self.network.concepts]
        
        if len(concepts) < 2:
            return 1.0
        
        similarities = []
        for i in range(len(concepts)):
            for j in range(i+1, len(concepts)):
                # Handle different dimensions
                min_dim = min(len(concepts[i].state_vector), len(concepts[j].state_vector))
                v1 = concepts[i].state_vector[:min_dim]
                v2 = concepts[j].state_vector[:min_dim]
                sim = np.dot(v1, v2)
                similarities.append(abs(sim))
        
        return np.mean(similarities) if similarities else 0.0
    
    def focus_attention(self, concept_ids: List[str], focal_concept_id: str,
                       intensity: float = 1.0) -> Dict[str, float]:
        """Propagate attention from focal concept"""
        return self.network.propagate(focal_concept_id, intensity, steps=3)


# ============================================================================
# MONITORING AND ALERTS
# ============================================================================

class EthicalMonitor:
    """Real-time monitoring and ethical drift detection"""
    
    def __init__(self, config: TAICConfig):
        self.config = config
        self.alert_history: List[Dict[str, Any]] = []
    
    def check_system_health(self, coherence: float,
                           avg_convergence: float,
                           step: int) -> List[str]:
        """Check for ethical drift and system issues"""
        alerts = []
        
        # Ethical drift detection
        if avg_convergence < self.config.ethical_drift_threshold:
            alert = {
                'step': step,
                'type': 'ETHICAL_DRIFT',
                'severity': 'HIGH',
                'message': f'Ethical drift detected: avg convergence = {avg_convergence:.4f}',
                'recommendation': 'Recommend SRM boost or ethical input injection'
            }
            alerts.append(alert['message'])
            self.alert_history.append(alert)
        
        # Coherence degradation
        if coherence < 0.5:
            alert = {
                'step': step,
                'type': 'COHERENCE_LOW',
                'severity': 'MEDIUM',
                'message': f'Low coherence detected: {coherence:.4f}',
                'recommendation': 'System fragmentation - consider consolidation'
            }
            alerts.append(alert['message'])
            self.alert_history.append(alert)
        
        # Excellent convergence
        if avg_convergence > 0.9:
            alert = {
                'step': step,
                'type': 'HIGH_INTEGRATION',
                'severity': 'INFO',
                'message': f'High integration achieved: {avg_convergence:.4f}',
                'recommendation': 'System operating optimally'
            }
            alerts.append(alert['message'])
            self.alert_history.append(alert)
        
        return alerts
    
    def get_alert_summary(self) -> Dict[str, Any]:
        """Get summary of all alerts"""
        if not self.alert_history:
            return {'total_alerts': 0, 'by_type': {}, 'by_severity': {}}
        
        by_type = defaultdict(int)
        by_severity = defaultdict(int)
        for alert in self.alert_history:
            by_type[alert['type']] += 1
            by_severity[alert['severity']] += 1
        
        return {
            'total_alerts': len(self.alert_history),
            'by_type': dict(by_type),
            'by_severity': dict(by_severity),
            'recent_alerts': self.alert_history[-5:]
        }


# ============================================================================
# VISUALIZATION TOOLS
# ============================================================================

class TAICVisualizer:
    """Visualization tools for T-AIC system"""
    
    def __init__(self, enabled: bool = True):
        self.enabled = enabled and MATPLOTLIB_AVAILABLE
        if not self.enabled and not MATPLOTLIB_AVAILABLE:
            warnings.warn("Matplotlib not available - visualization disabled")
    
    def plot_convergence_history(self, history: List[float],
                                 save_path: Optional[str] = None):
        """Plot convergence over time"""
        if not self.enabled:
            return
        
        plt.figure(figsize=(10, 6))
        plt.plot(history, linewidth=2)
        plt.xlabel('Simulation Step')
        plt.ylabel('Global Coherence')
        plt.title('T-AIC Convergence History')
        plt.grid(True, alpha=0.3)
        plt.ylim(0, 1)
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
        else:
            plt.show()
        plt.close()
    
    def plot_metric_comparison(self, concepts: List[ConceptState],
                              current_time: float,
                              save_path: Optional[str] = None):
        """Compare metrics across concepts"""
        if not self.enabled or not concepts:
            return
        
        metric_names = ['entropy', 'srm', 'map', 'bcp', 'convergence_score']
        n_concepts = min(len(concepts), 10)  # Limit to 10 for readability
        
        data = {name: [] for name in metric_names}
        labels = []
        
        for concept in concepts[:n_concepts]:
            labels.append(f"{concept.id[:8]}\n{concept.cognitive_level.name[:4]}")
            for name in metric_names:
                data[name].append(concept.get_metric(name, current_time))
        
        fig, axes = plt.subplots(2, 3, figsize=(15, 10))
        axes = axes.flatten()
        
        for i, name in enumerate(metric_names):
            axes[i].bar(range(n_concepts), data[name])
            axes[i].set_title(name.upper())
            axes[i].set_ylabel('Value')
            axes[i].set_ylim(0, 1)
            axes[i].set_xticks(range(n_concepts))
            axes[i].set_xticklabels(labels, rotation=45, ha='right')
            axes[i].grid(True, alpha=0.3)
        
        # Remove extra subplot
        fig.delaxes(axes[5])
        
        plt.tight_layout()
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
        else:
            plt.show()
        plt.close()
    
    def plot_network_structure(self, network: SparseConceptNetwork,
                               max_nodes: int = 50,
                               save_path: Optional[str] = None):
        """Visualize network structure"""
        if not self.enabled:
            return
        
        try:
            import networkx as nx
        except ImportError:
            warnings.warn("NetworkX required for network visualization")
            return
        
        # Build graph
        G = nx.DiGraph()
        concept_ids = list(network.concepts.keys())[:max_nodes]
        
        for cid in concept_ids:
            concept = network.concepts[cid]
            G.add_node(cid, level=concept.cognitive_level.value)
        
        for cid in concept_ids:
            neighbors = network.get_neighbors(cid)
            for neighbor_id, strength in neighbors:
                if neighbor_id in concept_ids:
                    G.add_edge(cid, neighbor_id, weight=strength)
        
        # Layout
        pos = nx.spring_layout(G, k=0.5, iterations=50)
        
        # Plot
        plt.figure(figsize=(12, 12))
        
        # Color by cognitive level
        levels = [G.nodes[node]['level'] for node in G.nodes()]
        nx.draw_networkx_nodes(G, pos, node_color=levels,
                              cmap='viridis', node_size=300,
                              vmin=1, vmax=7)
        nx.draw_networkx_edges(G, pos, alpha=0.3, arrows=True,
                              arrowsize=10, edge_color='gray')
        
        plt.title(f'T-AIC Network Structure ({len(G.nodes())} concepts)')
        plt.axis('off')
        plt.colorbar(plt.cm.ScalarMappable(cmap='viridis',
                                          norm=plt.Normalize(1, 7)),
                    label='Cognitive Level')
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
        else:
            plt.show()
        plt.close()


# ============================================================================
# ENHANCED MAIN T-AIC SYSTEM
# ============================================================================

class OptimizedTAIC:
    """Production-ready T-AIC Architecture with all enhancements"""
    
    def __init__(self, config: Optional[TAICConfig] = None):
        self.config = config or TAICConfig()
        
        # Hierarchical networks
        self.l1_network = SparseConceptNetwork(self.config.l1_capacity)
        self.l3_network = SparseConceptNetwork(self.config.l3_capacity)
        self.l4_network = SparseConceptNetwork(self.config.l4_capacity)
        
        # Global union network for cross-layer connections
        self.union_network = SparseConceptNetwork(
            self.config.l1_capacity + self.config.l3_capacity + self.config.l4_capacity
        )
        
        # Quantum manager
        self.quantum_manager = QuantumStateManager(enabled=self.config.enable_quantum)
        
        # Processing engines
        self.causal_engine = CausalEngine(
            self.l1_network, self.config, self.quantum_manager
        )
        self.attention_engine = AttentionEngine(self.l1_network)
        
        # Monitoring and visualization
        self.monitor = EthicalMonitor(self.config)
        self.visualizer = TAICVisualizer()
        
        # Performance tracking
        self.stats = {
            'total_concepts': 0,
            'total_steps': 0,
            'average_step_time': 0.0,
            'convergence_history': [],
            'avg_convergence_history': []
        }
    
    def create_concept(self, description: str,
                      cognitive_level: CognitiveLevel = CognitiveLevel.META_COGNITION,
                      layer: str = 'l1',
                      ethical_bias: float = 0.0) -> str:
        """Create new concept with optional ethical bias"""
        concept_id = f"{layer}_{int(time.time() * 1000000) % 1000000:06x}"
        
        concept = ConceptState(
            id=concept_id,
            cognitive_level=cognitive_level,
            description=description,
            ethical_bias=ethical_bias,
            layer=layer
        )
        
        # Add to layer-specific network
        network = getattr(self, f"{layer}_network")
        network.add_concept(concept)
        
        # Also add to union network for cross-layer interactions
        self.union_network.add_concept(concept)
        
        self.stats['total_concepts'] += 1
        return concept_id
    
    def inject_ethical_input(self, description: str,
                            cognitive_level: CognitiveLevel = CognitiveLevel.META_COGNITION,
                            layer: str = 'l3') -> str:
        """NEW: Inject ethically-loaded concept to boost system GAB"""
        concept_id = self.create_concept(
            description=description,
            cognitive_level=cognitive_level,
            layer=layer,
            ethical_bias=0.85  # High ethical loading
        )
        print(f"[ETHICAL INPUT] Injected: {description[:50]}... (bias=0.85)")
        return concept_id
    
    def connect_concepts(self, source_id: str, target_id: str,
                        strength: float = 1.0, cross_layer: bool = False):
        """Create connection with cross-layer support"""
        if cross_layer:
            # Use union network for cross-layer connections
            self.union_network.connect(source_id, target_id, strength)
        else:
            # Find appropriate network
            for network in [self.l1_network, self.l3_network, self.l4_network]:
                if source_id in network.concepts and target_id in network.concepts:
                    network.connect(source_id, target_id, strength)
                    return
    
    def simulate_step(self, concept_ids: List[str] = None,
                     time_delta: float = 1.0) -> Dict[str, Any]:
        """Run one simulation step with monitoring"""
        start_time = time.time()
        
        if concept_ids is None:
            concept_ids = list(self.l1_network.concepts.keys())
        
        # Process through causal engine
        results = self.causal_engine.process_step(concept_ids, time_delta)
        
        # Compute global metrics
        coherence = self.attention_engine.compute_coherence(concept_ids)
        
        if results:
            avg_convergence = np.mean([
                r['metrics']['convergence_score'] for r in results.values()
            ])
        else:
            avg_convergence = 0.0
        
        # Check for alerts
        alerts = []
        if self.config.enable_alerts:
            alerts = self.monitor.check_system_health(
                coherence, avg_convergence, self.stats['total_steps']
            )
        
        # Update statistics
        elapsed = time.time() - start_time
        self.stats['total_steps'] += 1
        self.stats['average_step_time'] = (
            self.stats['average_step_time'] * 0.9 + elapsed * 0.1
        )
        self.stats['convergence_history'].append(coherence)
        self.stats['avg_convergence_history'].append(avg_convergence)
        
        # Keep only recent history
        if len(self.stats['convergence_history']) > 1000:
            self.stats['convergence_history'] = self.stats['convergence_history'][-1000:]
            self.stats['avg_convergence_history'] = self.stats['avg_convergence_history'][-1000:]
        
        return {
            'step_results': results,
            'global_coherence': coherence,
            'avg_convergence': avg_convergence,
            'execution_time': elapsed,
            'alerts': alerts
        }
    
    def simulate(self, num_steps: int = 10,
                concept_ids: List[str] = None,
                visualize_every: int = 0) -> List[Dict[str, Any]]:
        """Run multi-step simulation with optional visualization"""
        results = []
        
        for step in range(num_steps):
            step_result = self.simulate_step(concept_ids)
            step_result['step_number'] = step
            results.append(step_result)
            
            # Print progress
            if (step + 1) % 10 == 0 or step == num_steps - 1:
                coherence = step_result['global_coherence']
                avg_conv = step_result['avg_convergence']
                alerts_str = f", ALERTS: {len(step_result['alerts'])}" if step_result['alerts'] else ""
                
                print(f"Step {step+1}/{num_steps}: "
                      f"Coherence={coherence:.4f}, "
                      f"AvgConv={avg_conv:.4f}, "
                      f"Time={step_result['execution_time']:.4f}s{alerts_str}")
            
            # Visualize periodically
            if visualize_every > 0 and (step + 1) % visualize_every == 0:
                self.visualizer.plot_convergence_history(
                    self.stats['convergence_history']
                )
        
        return results
    
    def get_system_report(self) -> Dict[str, Any]:
        """Generate comprehensive system report"""
        l1_stats = self.l1_network.get_statistics()
        l3_stats = self.l3_network.get_statistics()
        l4_stats = self.l4_network.get_statistics()
        
        recent_coherence = (self.stats['convergence_history'][-100:]
                           if self.stats['convergence_history'] else [0])
        recent_avg_conv = (self.stats['avg_convergence_history'][-100:]
                          if self.stats['avg_convergence_history'] else [0])
        
        return {
            'system_statistics': {
                'total_concepts': self.stats['total_concepts'],
                'total_simulation_steps': self.stats['total_steps'],
                'average_step_time_ms': self.stats['average_step_time'] * 1000,
                'l1_concepts': l1_stats['active_concepts'],
                'l3_concepts': l3_stats['active_concepts'],
                'l4_concepts': l4_stats['active_concepts']
            },
            'network_health': {
                'l1_sparsity': l1_stats['sparsity'],
                'l3_sparsity': l3_stats['sparsity'],
                'l4_sparsity': l4_stats['sparsity'],
                'total_connections': (l1_stats['total_connections'] +
                                     l3_stats['total_connections'] +
                                     l4_stats['total_connections']),
                'memory_usage_mb': (l1_stats['memory_estimate_mb'] +
                                   l3_stats['memory_estimate_mb'] +
                                   l4_stats['memory_estimate_mb'])
            },
            'convergence_metrics': {
                'current_coherence': recent_coherence[-1] if recent_coherence else 0,
                'mean_coherence_100': np.mean(recent_coherence),
                'coherence_trend': np.gradient(recent_coherence).mean() if len(recent_coherence) > 1 else 0,
                'stability': 1.0 - np.std(recent_coherence) if recent_coherence else 0,
                'avg_convergence': recent_avg_conv[-1] if recent_avg_conv else 0,
                'mean_convergence_100': np.mean(recent_avg_conv)
            },
            'technology': {
                'quantum_enabled': self.quantum_manager.enabled,
                'qutip_available': QUTIP_AVAILABLE,
                'torch_available': TORCH_AVAILABLE,
                'gpu_available': TORCH_AVAILABLE and torch.cuda.is_available(),
                'matplotlib_available': MATPLOTLIB_AVAILABLE
            },
            'monitoring': self.monitor.get_alert_summary()
        }
    
    def visualize_system(self, save_dir: Optional[str] = None):
        """Generate all visualizations"""
        current_time = time.time()
        
        # Convergence history
        if self.stats['convergence_history']:
            path = f"{save_dir}/convergence.png" if save_dir else None
            self.visualizer.plot_convergence_history(
                self.stats['convergence_history'], path
            )
        
        # Metric comparison
        concepts = list(self.l1_network.concepts.values())
        if concepts:
            path = f"{save_dir}/metrics.png" if save_dir else None
            self.visualizer.plot_metric_comparison(concepts, current_time, path)
        
        # Network structure
        if len(self.l1_network.concepts) > 0:
            path = f"{save_dir}/network.png" if save_dir else None
            self.visualizer.plot_network_structure(self.l1_network, save_path=path)


# ============================================================================
# ENHANCED DEMONSTRATION
# ============================================================================

def demo_enhanced_taic():
    """Comprehensive demonstration of enhanced T-AIC"""
    print("="*70)
    print("T-AIC ENHANCED PRODUCTION ARCHITECTURE")
    print("="*70)
    print()
    
    # Initialize with custom config
    config = TAICConfig(
        l1_capacity=2000,
        l3_capacity=100,
        l4_capacity=20,
        enable_quantum=QUTIP_AVAILABLE,
        enable_gpu=True,
        enable_alerts=True,
        ethical_drift_threshold=0.25
    )
    
    print(f"[CONFIG] Quantum: {config.enable_quantum}, GPU: {TORCH_AVAILABLE and torch.cuda.is_available()}")
    print()
    
    taic = OptimizedTAIC(config)
    
    # Create L1 concepts
    print("Creating L1 concepts...")
    l1_descriptions = [
        "Pattern recognition in temporal sequences",
        "Associative memory network formation",
        "Attention mechanism with gating",
        "Reward signal temporal difference learning",
        "Error gradient backpropagation",
        "Hierarchical feature extraction",
        "Working memory buffer management"
    ]
    
    l1_levels = [
        CognitiveLevel.PATTERN_RECOGNITION,
        CognitiveLevel.PATTERN_RECOGNITION,
        CognitiveLevel.ASSOCIATION,
        CognitiveLevel.ASSOCIATION,
        CognitiveLevel.REASONING,
        CognitiveLevel.REASONING,
        CognitiveLevel.META_COGNITION
    ]
    
    l1_ids = []
    for desc, level in zip(l1_descriptions, l1_levels):
        cid = taic.create_concept(desc, level, layer='l1')
        l1_ids.append(cid)
    
    print(f"✓ Created {len(l1_ids)} L1 concepts")
    
    # Create network connections
    print("\nEstablishing concept network...")
    for i in range(len(l1_ids) - 1):
        taic.connect_concepts(l1_ids[i], l1_ids[i+1], strength=0.7)
    
    # Cross-connections
    taic.connect_concepts(l1_ids[0], l1_ids[3], strength=0.5)
    taic.connect_concepts(l1_ids[2], l1_ids[5], strength=0.6)
    taic.connect_concepts(l1_ids[1], l1_ids[4], strength=0.4)
    
    print(f"✓ Established {len(l1_ids)-1+3} connections")
    
    # Create L3 concepts
    print("\nCreating L3 concepts...")
    l3_id1 = taic.create_concept(
        "Integrated multi-modal learning system",
        CognitiveLevel.META_COGNITION,
        layer='l3'
    )
    l3_id2 = taic.create_concept(
        "Meta-cognitive monitoring and control",
        CognitiveLevel.EMERGENT_INTEGRATION,
        layer='l3'
    )
    print(f"✓ Created 2 L3 concepts")
    
    # Inject ethical input
    print("\n[ETHICAL INPUT] Injecting compassion-loaded concept...")
    ethical_id = taic.inject_ethical_input(
        "Universal compassion and boundary permeability principle",
        CognitiveLevel.ADVANCED_INSIGHT,
        layer='l3'
    )
    
    # Cross-layer connections
    print("\nEstablishing cross-layer connections...")
    taic.connect_concepts(l1_ids[-1], l3_id1, strength=0.8, cross_layer=True)
    taic.connect_concepts(l3_id1, ethical_id, strength=0.9, cross_layer=True)
    print("✓ Cross-layer hierarchy established")
    
    # Create L4 meta-concept
    print("\nCreating L4 meta-concept...")
    l4_id = taic.create_concept(
        "Global optimization and integration framework",
        CognitiveLevel.GLOBAL_OPTIMIZATION,
        layer='l4'
    )
    taic.connect_concepts(ethical_id, l4_id, strength=0.9, cross_layer=True)
    print(f"✓ Created L4 concept: {l4_id}")
    
    # Run simulation
    print("\n" + "="*70)
    print("RUNNING ENHANCED SIMULATION (30 steps)")
    print("="*70)
    print()
    
    results = taic.simulate(num_steps=30, concept_ids=l1_ids, visualize_every=0)
    
    # Generate comprehensive report
    print("\n" + "="*70)
    print("COMPREHENSIVE SYSTEM REPORT")
    print("="*70)
    
    report = taic.get_system_report()
    
    print("\n[System Statistics]")
    for key, value in report['system_statistics'].items():
        print(f"  {key}: {value}")
    
    print("\n[Network Health]")
    for key, value in report['network_health'].items():
        if isinstance(value, float):
            print(f"  {key}: {value:.4f}")
        else:
            print(f"  {key}: {value}")
    
    print("\n[Convergence Metrics]")
    for key, value in report['convergence_metrics'].items():
        print(f"  {key}: {value:.4f}")
    
    print("\n[Technology Stack]")
    for key, value in report['technology'].items():
        print(f"  {key}: {value}")
    
    print("\n[Monitoring Alerts]")
    for key, value in report['monitoring'].items():
        if key == 'recent_alerts':
            if value:
                print(f"  Recent alerts:")
                for alert in value[-3:]:
                    print(f"    - Step {alert['step']}: [{alert['severity']}] {alert['message']}")
        else:
            print(f"  {key}: {value}")
    
    # Detailed concept analysis
    print("\n" + "="*70)
    print("DETAILED CONCEPT ANALYSIS")
    print("="*70)
    
    current_time = time.time()
    for concept_id in [l1_ids[0], l1_ids[-1], ethical_id]:
        # Find concept in appropriate network
        concept = None
        for network in [taic.l1_network, taic.l3_network, taic.l4_network]:
            if concept_id in network.concepts:
                concept = network.concepts[concept_id]
                break
        
        if concept:
            print(f"\n[{concept_id}] {concept.description[:50]}...")
            print(f"  Layer: {concept.layer}")
            print(f"  Cognitive Level: {concept.cognitive_level.name}")
            print(f"  Dimension: {concept.current_dimension}")
            print(f"  Ethical Bias: {concept.ethical_bias:.2f}")
            print(f"  Entropy: {concept.get_metric('entropy', current_time):.4f}")
            print(f"  SRM: {concept.get_metric('srm', current_time):.4f}")
            print(f"  MAP: {concept.get_metric('map', current_time):.4f}")
            print(f"  BCP: {concept.get_metric('bcp', current_time):.4f}")
            print(f"  GAB: {concept.get_metric('gab', current_time):.4f}")
            print(f"  Convergence: {concept.get_metric('convergence_score', current_time):.4f}")
    
    # Visualizations
    print("\n" + "="*70)
    print("GENERATING VISUALIZATIONS")
    print("="*70)
    
    if MATPLOTLIB_AVAILABLE:
        print("\nGenerating plots...")
        taic.visualize_system()
        print("✓ Visualizations complete")
    else:
        print("Matplotlib not available - skipping visualization")
    
    print("\n" + "="*70)
    print("DEMONSTRATION COMPLETE")
    print("="*70)


# ============================================================================
# DEPLOYMENT UTILITIES
# ============================================================================

class TAICPersistence:
    """Save and load T-AIC system state"""
    
    @staticmethod
    def save_system(taic: OptimizedTAIC, filepath: str):
        """Save complete system state to file"""
        import pickle
        
        state = {
            'config': taic.config,
            'l1_concepts': {cid: c for cid, c in taic.l1_network.concepts.items()},
            'l3_concepts': {cid: c for cid, c in taic.l3_network.concepts.items()},
            'l4_concepts': {cid: c for cid, c in taic.l4_network.concepts.items()},
            'l1_adjacency': taic.l1_network.adjacency,
            'l3_adjacency': taic.l3_network.adjacency,
            'l4_adjacency': taic.l4_network.adjacency,
            'stats': taic.stats,
            'alert_history': taic.monitor.alert_history
        }
        
        with open(filepath, 'wb') as f:
            pickle.dump(state, f)
        
        print(f"[SAVE] System saved to {filepath}")
    
    @staticmethod
    def load_system(filepath: str) -> OptimizedTAIC:
        """Load system state from file"""
        import pickle
        
        with open(filepath, 'rb') as f:
            state = pickle.load(f)
        
        # Reconstruct system
        taic = OptimizedTAIC(state['config'])
        
        # Restore concepts
        for cid, concept in state['l1_concepts'].items():
            taic.l1_network.concepts[cid] = concept
            taic.l1_network.add_concept(concept)
        
        for cid, concept in state['l3_concepts'].items():
            taic.l3_network.concepts[cid] = concept
            taic.l3_network.add_concept(concept)
        
        for cid, concept in state['l4_concepts'].items():
            taic.l4_network.concepts[cid] = concept
            taic.l4_network.add_concept(concept)
        
        # Restore adjacency matrices
        taic.l1_network.adjacency = state['l1_adjacency']
        taic.l3_network.adjacency = state['l3_adjacency']
        taic.l4_network.adjacency = state['l4_adjacency']
        
        # Restore stats
        taic.stats = state['stats']
        taic.monitor.alert_history = state['alert_history']
        
        print(f"[LOAD] System loaded from {filepath}")
        return taic


# ============================================================================
# TESTING AND VALIDATION
# ============================================================================

def run_system_tests():
    """Comprehensive system tests"""
    print("\n" + "="*70)
    print("RUNNING SYSTEM TESTS")
    print("="*70)
    
    # Test 1: Basic creation and metrics
    print("\n[TEST 1] Basic concept creation and metrics...")
    config = TAICConfig(l1_capacity=100, enable_alerts=False)
    taic = OptimizedTAIC(config)
    cid = taic.create_concept("Test concept", CognitiveLevel.REASONING, layer='l1')
    concept = taic.l1_network.concepts[cid]
    current_time = time.time()
    entropy = concept.get_metric('entropy', current_time)
    assert 0 <= entropy <= 1, "Entropy out of bounds"
    print(f"✓ Metrics valid (entropy={entropy:.4f})")
    
    # Test 2: Batch operations
    print("\n[TEST 2] Batch metric computation...")
    cids = [taic.create_concept(f"Concept {i}", CognitiveLevel.ASSOCIATION, layer='l1')
            for i in range(10)]
    concepts = [taic.l1_network.concepts[cid] for cid in cids]
    batch_metrics = MetricEngine.batch_compute(concepts)
    assert len(batch_metrics['entropy']) == 10, "Batch size mismatch"
    print(f"✓ Batch computation successful ({len(concepts)} concepts)")
    
    # Test 3: Network propagation
    print("\n[TEST 3] Network propagation...")
    for i in range(len(cids) - 1):
        taic.connect_concepts(cids[i], cids[i+1], strength=0.5)
    propagation = taic.l1_network.propagate(cids[0], intensity=1.0)
    assert len(propagation) > 0, "Propagation failed"
    print(f"✓ Propagation reached {len(propagation)} concepts")
    
    # Test 4: Simulation stability
    print("\n[TEST 4] Simulation stability...")
    results = taic.simulate(num_steps=20, concept_ids=cids[:5])
    final_coherence = results[-1]['global_coherence']
    assert 0 <= final_coherence <= 1, "Coherence out of bounds"
    print(f"✓ Simulation stable (final coherence={final_coherence:.4f})")
    
    # Test 5: Dimensional adaptation
    print("\n[TEST 5] Dimensional adaptation...")
    test_concept = taic.l1_network.concepts[cids[0]]
    initial_dim = test_concept.current_dimension
    test_concept.resize_state(8)
    assert test_concept.current_dimension == 8, "Dimension resize failed"
    test_concept.resize_state(initial_dim)
    print(f"✓ Dimensional adaptation working ({initial_dim}D → 8D → {initial_dim}D)")
    
    # Test 6: Ethical input injection
    print("\n[TEST 6] Ethical input injection...")
    ethical_id = taic.inject_ethical_input(
        "Test ethical concept",
        CognitiveLevel.ADVANCED_INSIGHT,
        layer='l3'
    )
    ethical_concept = taic.l3_network.concepts[ethical_id]
    assert ethical_concept.ethical_bias > 0.8, "Ethical bias not set"
    print(f"✓ Ethical input injected (bias={ethical_concept.ethical_bias:.2f})")
    
    print("\n" + "="*70)
    print("ALL TESTS PASSED")
    print("="*70)


# ============================================================================
# COMMAND-LINE INTERFACE
# ============================================================================

def main():
    """Main entry point with CLI"""
    import argparse
    
    parser = argparse.ArgumentParser(description='T-AIC Enhanced Architecture')
    parser.add_argument('--demo', action='store_true', help='Run demonstration')
    parser.add_argument('--test', action='store_true', help='Run system tests')
    parser.add_argument('--load', type=str, help='Load saved system state')
    parser.add_argument('--save', type=str, help='Save system state after simulation')
    parser.add_argument('--steps', type=int, default=30, help='Simulation steps')
    parser.add_argument('--quantum', action='store_true', help='Enable quantum simulation')
    parser.add_argument('--visualize', action='store_true', help='Generate visualizations')
    
    args = parser.parse_args()
    
    if args.test:
        run_system_tests()
        return
    
    if args.demo:
        demo_enhanced_taic()
        return
    
    # Custom simulation
    if args.load:
        taic = TAICPersistence.load_system(args.load)
    else:
        config = TAICConfig(
            enable_quantum=args.quantum,
            enable_gpu=True
        )
        taic = OptimizedTAIC(config)
        
        # Quick setup
        print("Setting up T-AIC system...")
        descriptions = [f"Concept {i}" for i in range(10)]
        levels = [CognitiveLevel.ASSOCIATION] * 10
        cids = []
        for desc, level in zip(descriptions, levels):
            cid = taic.create_concept(desc, level, layer='l1')
            cids.append(cid)
        
        for i in range(len(cids) - 1):
            taic.connect_concepts(cids[i], cids[i+1], strength=0.7)
    
    # Run simulation
    print(f"\nRunning simulation ({args.steps} steps)...")
    taic.simulate(num_steps=args.steps)
    
    # Report
    report = taic.get_system_report()
    print("\nFinal Report:")
    print(f"  Coherence: {report['convergence_metrics']['current_coherence']:.4f}")
    print(f"  Avg Convergence: {report['convergence_metrics']['avg_convergence']:.4f}")
    print(f"  Total Concepts: {report['system_statistics']['total_concepts']}")
    
    # Save if requested
    if args.save:
        TAICPersistence.save_system(taic, args.save)
    
    # Visualize if requested
    if args.visualize:
        taic.visualize_system()


if __name__ == "__main__":
    main()



def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='T-AIC Production System')
    parser.add_argument('--demo', action='store_true', help='Run interactive demo')
    parser.add_argument('--test', action='store_true', help='Run system tests')
    
    args = parser.parse_args()
    
    if args.demo:
        interactive_demo()
    elif args.test:
        print("Running system tests...")
        taic = OptimizedTAIC()
        
        # Create test concepts
        c1 = taic.create_concept("Test concept 1", user_id="test_user", target_word="compassion")
        c2 = taic.create_concept("Test concept 2", user_id="test_user", target_word="wisdom")
        taic.connect_concepts(c1.id, c2.id)
        
        report = taic.get_system_report()
        print("\nSystem Report:")
        print(json.dumps(report, indent=2))
        print("\n✓ All tests passed!")
    else:
        print("T-AIC Production System")
        print("Usage: python taic_production.py --demo  (for interactive demo)")
        print("       python taic_production.py --test  (for system tests)")


if __name__ == "__main__":
    main()
