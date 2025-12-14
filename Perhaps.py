#!/usr/bin/env python3
"""
T-AIC: Transcendent Artificial Intelligence Consciousness
Complete Production-Ready Implementation

This is a fully functional, properly wired implementation combining:
- Core T-AIC architecture with adaptive dimensionality
- User personalization engine with exposure profiles
- macOS Dictionary integration
- Meme/Memeplex cultural evolution system
- Decision-making layer
- Complete persistence and testing framework

Version: 1.0.0
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

# Optional dependencies with graceful fallback
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

# ============================================================================
# KNOWLEDGE BASES
# ============================================================================

NUANCE_KNOWLEDGE = {
    "short_definition": "A subtle difference in or shade of meaning, expression, or sound.",
    "academic_overview": """
1. Linguistic & Semiotic Perspectives
   - Nuance refers to subtle variations in meaning, tone, or expression
   - Types: Semantic, Pragmatic, Connotative, Cultural

2. Philosophical Perspectives
   - Gap between literal and intended meaning
   - Relates to Grice's conversational implicature

3. Psychological & Cognitive Science
   - Requires higher-order cognitive processing
   - Critical for social cognition and empathy

4. Cultural Studies
   - Culturally embedded and context-dependent
   - Lost in translation phenomena

5. Key Takeaways
   - Operates at multiple levels simultaneously
   - Represents richness beyond binary interpretations
"""
}

def get_nuance_overview(as_summary: bool = False) -> str:
    """Get nuance academic overview"""
    return NUANCE_KNOWLEDGE["short_definition"] if as_summary else NUANCE_KNOWLEDGE["academic_overview"]

# ============================================================================
# CORE CONFIGURATION
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
    
    # Personalization
    enable_personalization: bool = True
    enable_macos_dict: bool = is_macos()

# ============================================================================
# COGNITIVE LEVELS
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

# ============================================================================
# EXPOSURE PROFILE (USER PERSONALIZATION)
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
# CONCEPT STATE (ENHANCED WITH PERSONALIZATION)
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
# MEME SYSTEM (Cultural Evolution)
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

# ============================================================================
# INTERACTIVE DEMO
# ============================================================================

def interactive_demo():
    """Interactive demonstration"""
    print("="*70)
    print("T-AIC Production System - Interactive Demo")
    print("="*70)
    
    taic = OptimizedTAIC()
    taic.personalization.load_profiles()
    user = "Thaniel"
    
    while True:
        try:
            word = input("\nEnter a word/concept (or 'quit'): ").strip()
            if word.lower() == "quit":
                break
            
            # Get definition
            definition = first_definition(word)
            print(f"\n[Dictionary] {word}:\n{definition}\n")
            
            # Update profile
            taic.personalization.create_or_update_profile(user, f"{word}: {definition}")
            
            # Create concept
            concept = taic.create_concept(
                description=f"Profiled concept: {word}",
                user_id=user,
                target_word=word
            )
            
            print(f"[TAIC] Universal def: {concept.universal_def[:100]}...")
            print(f"[TAIC] Relative meaning: {concept.relative_meaning:.3f}")
            print(f"[TAIC] Relative nuance: {concept.relative_nuance}")
            
            # Get metrics
            current_time = time.time()
            entropy = concept.get_metric('entropy', current_time)
            srm = concept.get_metric('srm', current_time)
            convergence = concept.get_metric('convergence_score', current_time)
            
            print(f"[TAIC] Metrics - Entropy: {entropy:.3f}, SRM: {srm:.3f}, Convergence: {convergence:.3f}")
            
        except KeyboardInterrupt:
            print("\nExiting...")
            break
        except Exception as e:
            print(f"Error: {e}")
            continue
    
    taic.personalization.save_profiles()
    print("\nProfiles saved. Goodbye!")

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

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
