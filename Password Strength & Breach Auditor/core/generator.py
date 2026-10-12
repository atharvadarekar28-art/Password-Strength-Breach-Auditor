"""
Cryptographically Secure Password & Passphrase Generator.
Uses Python's secrets module for high-entropy generation.
Supports both random character passwords and Diceware-style multi-word passphrases.
"""

import secrets
import string
from typing import List

# Curated list of distinct memorable words for Diceware passphrase generation
DICEWARE_WORDS = [
    "abandon", "ability", "absent", "absorb", "abstract", "academic", "accent", "acoustic",
    "action", "actor", "actress", "adapter", "admiral", "advice", "aerobic", "affair",
    "afford", "agency", "agent", "agile", "airline", "airport", "album", "alchemy",
    "alert", "algebra", "alibi", "alien", "almond", "alpine", "alumni", "amber",
    "ambition", "amend", "amount", "anchor", "ancient", "android", "angel", "angler",
    "animate", "antenna", "anthem", "antique", "anvil", "apology", "apple", "apron",
    "arcade", "arctic", "arena", "armory", "arrow", "artifact", "artist", "aspect",
    "assault", "asset", "atlas", "atom", "atomic", "attic", "auction", "audio",
    "aurora", "author", "auto", "autumn", "avatar", "avenue", "avocado", "awake",
    "award", "aware", "axis", "badger", "bagel", "bakery", "balance", "balcony",
    "ballad", "bamboo", "banana", "banner", "barber", "bark", "barrel", "baron",
    "barrier", "base", "basic", "basin", "basket", "battery", "battle", "beacon",
    "beam", "beast", "beauty", "beaver", "beetle", "bell", "bench", "berry",
    "bicycle", "binary", "biology", "birch", "biscuit", "bishop", "bitter", "blade",
    "blanket", "blender", "blimp", "blizzard", "block", "blossom", "blueberry", "board",
    "boat", "boiler", "bold", "bonus", "book", "border", "botany", "bottle",
    "bounce", "bracket", "brain", "branch", "brass", "brave", "breeze", "brick",
    "bridge", "brisk", "bronze", "bubble", "bucket", "buffer", "builder", "bullet",
    "bundle", "bunker", "burst", "bus", "cabin", "cable", "cactus", "cadet",
    "cage", "cake", "calendar", "calm", "camera", "camp", "canary", "candle",
    "candy", "canoe", "canvas", "canyon", "capital", "capsule", "captain", "capture",
    "caravan", "carbon", "card", "cargo", "carousel", "carpet", "carrot", "carton",
    "cascade", "castle", "catalyst", "catch", "cater", "cathedral", "cattle", "causeway",
    "caviar", "cedar", "ceiling", "cell", "celsius", "cement", "census", "ceramic",
    "cereal", "champion", "channel", "chaos", "charcoal", "chariot", "cheer", "cheese",
    "cheetah", "chemist", "cherry", "chest", "chimney", "chip", "chirp", "chocolate",
    "chorus", "chrome", "chronicle", "cider", "cigar", "cinema", "cinnamon", "circle",
    "circuit", "citizen", "citrus", "civic", "clam", "clamp", "classic", "cliff",
    "climate", "climb", "clinic", "clock", "cloth", "cloud", "clover", "clutch",
    "coast", "cobalt", "cobra", "coconut", "coffee", "coin", "cold", "collar",
    "colony", "comet", "compass", "complex", "composer", "conduit", "coral", "corridor",
    "cotton", "cougar", "cradle", "craft", "crane", "crater", "crayfish", "credit",
    "creek", "crescent", "crest", "cricket", "crimson", "crisis", "crisp", "crocus",
    "cruise", "crunch", "crystal", "cube", "culprit", "cupboard", "curfew", "curious",
    "curtain", "cushion", "custom", "cylinder", "dagger", "dairy", "daisy", "damage",
    "danger", "daring", "dash", "database", "dawn", "daybreak", "dazzle", "dealer",
    "debate", "debris", "december", "decimal", "decision", "deck", "declare", "decoder",
    "defense", "defiant", "degree", "delta", "deluxe", "demand", "demise", "denial",
    "density", "deposit", "deputy", "desert", "design", "desk", "dessert", "destroy",
    "detect", "device", "dew", "diamond", "diary", "diet", "differ", "digit",
    "dignity", "dilemma", "dinner", "dinosaur", "diploma", "direct", "dirt", "disaster",
    "disco", "discord", "disease", "dish", "dismiss", "disorder", "display", "distance",
    "diver", "divide", "divorce", "dizzy", "doctor", "document", "dodge", "dogwood",
    "domain", "domino", "donkey", "donor", "donut", "door", "dorm", "double",
    "dove", "draft", "dragon", "drain", "drama", "drastic", "draw", "dream",
    "drift", "drill", "drink", "drizzle", "drop", "drum", "dry", "duck",
    "duct", "dugout", "dune", "duplicate", "durable", "dust", "duty", "dwarf",
    "dynamo", "eagle", "earth", "easel", "echo", "eclipse", "economy", "edge",
    "editor", "electric", "element", "elephant", "elite", "elm", "ember", "emerald",
    "emperor", "empire", "engine", "enigma", "enjoy", "enrich", "ensemble", "entry",
    "envelope", "epic", "episode", "equal", "equip", "era", "erase", "erosion",
    "escape", "essay", "essence", "estate", "eternal", "ether", "ethics", "evaporate",
    "evening", "evident", "evolve", "exact", "example", "excess", "exchange", "exotic",
    "expand", "expert", "explorer", "extend", "extra", "fabric", "factor", "falcon",
    "family", "famous", "fantasy", "farmer", "fashion", "feather", "federal", "fence",
    "fiber", "fiction", "field", "figure", "filter", "final", "finger", "firefly",
    "fiscal", "fish", "fitness", "flame", "flash", "flavor", "flicker", "flight",
    "flock", "flora", "flower", "fluid", "flute", "foam", "focus", "fog",
    "folder", "forest", "forge", "fossil", "foster", "fox", "fragment", "frame",
    "freckle", "freeze", "friction", "frog", "frontier", "frost", "frozen", "fruit",
    "fuel", "fumble", "funnel", "furnace", "fusion", "future", "gadget", "galaxy",
    "gallery", "garage", "garden", "garlic", "gasoline", "gateway", "gather", "gauge",
    "gazelle", "gear", "gemini", "general", "genius", "genre", "gentle", "geography",
    "germ", "ghost", "giant", "gift", "giggle", "ginger", "giraffe", "glacier",
    "glamour", "glass", "glider", "glimmer", "glimpse", "globe", "glory", "glove",
    "glow", "glucose", "goat", "gold", "golden", "goose", "gorilla", "gospel",
    "gossip", "govern", "grace", "grade", "gradient", "grain", "grand", "granite",
    "grape", "graph", "gravity", "gray", "great", "green", "grid", "grill",
    "grit", "grocery", "ground", "group", "grove", "grow", "guard", "guest",
    "guitar", "gulf", "gull", "gust", "gutter", "gymnast", "habitat", "hail",
    "hammer", "hamster", "handle", "harbor", "hardy", "harvest", "haven", "hawk",
    "hazel", "header", "health", "heart", "hearth", "hedge", "helium", "helmet",
    "herald", "herb", "heritage", "hero", "heron", "hickory", "highway", "hiking",
    "hill", "hint", "history", "hockey", "holiday", "hollow", "honey", "hood",
    "horizon", "horn", "horse", "hospital", "host", "hotel", "hound", "hourly",
    "hover", "hub", "humble", "humming", "humor", "hunter", "hurdle", "hurricane",
    "husky", "hybrid", "hydrant", "hydrogen", "hyena", "iceberg", "icon", "ideal",
    "iguana", "image", "impact", "impulse", "inch", "income", "index", "indigo",
    "infant", "infinite", "ink", "inlet", "input", "insect", "insight", "inspire",
    "instant", "integer", "intense", "interact", "interior", "inventor", "invest", "iron",
    "island", "isolate", "issue", "ivory", "jacket", "jaguar", "january", "jar",
    "jargon", "jasmine", "jasper", "jaw", "jazz", "jeans", "jelly", "jewel",
    "jigsaw", "join", "joke", "jolly", "journal", "journey", "judge", "juice",
    "jumbo", "jump", "jungle", "jupiter", "jury", "justice", "kangaroo", "kayak",
    "keeper", "kelp", "kernel", "kettle", "key", "keyboard", "kick", "kidney",
    "kimono", "kinetic", "kingdom", "kite", "kitten", "kiwi", "knee", "knife",
    "knight", "knot", "koala", "krypton", "label", "labor", "ladder", "lagoon",
    "lake", "lamp", "lantern", "laptop", "lark", "laser", "lattice", "lava",
    "layer", "leaf", "league", "leap", "legacy", "legend", "lemon", "leopard",
    "lesson", "letter", "lever", "liberty", "library", "lichen", "life", "light",
    "lightning", "lilac", "lily", "limb", "lime", "limit", "linen", "lion",
    "liquid", "lizard", "llama", "lobby", "lobster", "logic", "logistics", "lotus"
]

def generate_random_password(
    length: int = 16,
    use_upper: bool = True,
    use_lower: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    avoid_ambiguous: bool = False
) -> str:
    """Generates cryptographically random string password with guaranteed diversity."""
    char_pool = ""
    guaranteed = []

    upper_chars = string.ascii_uppercase
    lower_chars = string.ascii_lowercase
    digit_chars = string.digits
    symbol_chars = "!@#$%^&*()-_=+[]{}|;:,.<>?"

    if avoid_ambiguous:
        ambiguous = "l1IO0o"
        upper_chars = "".join(c for c in upper_chars if c not in ambiguous)
        lower_chars = "".join(c for c in lower_chars if c not in ambiguous)
        digit_chars = "".join(c for c in digit_chars if c not in ambiguous)

    if use_upper and upper_chars:
        char_pool += upper_chars
        guaranteed.append(secrets.choice(upper_chars))
    if use_lower and lower_chars:
        char_pool += lower_chars
        guaranteed.append(secrets.choice(lower_chars))
    if use_digits and digit_chars:
        char_pool += digit_chars
        guaranteed.append(secrets.choice(digit_chars))
    if use_symbols and symbol_chars:
        char_pool += symbol_chars
        guaranteed.append(secrets.choice(symbol_chars))

    if not char_pool:
        char_pool = string.ascii_letters + string.digits

    remaining_length = max(0, length - len(guaranteed))
    password_chars = guaranteed + [secrets.choice(char_pool) for _ in range(remaining_length)]

    # Cryptographically shuffle character order
    secrets.SystemRandom().shuffle(password_chars)
    return "".join(password_chars[:length])

def generate_diceware_passphrase(
    num_words: int = 4,
    separator: str = "-",
    capitalize: bool = True,
    include_number: bool = True
) -> str:
    """Generates Diceware multi-word passphrase like 'Correct-Horse-Battery-Staple'."""
    selected_words = [secrets.choice(DICEWARE_WORDS) for _ in range(num_words)]
    if capitalize:
        selected_words = [w.capitalize() for w in selected_words]

    if include_number:
        # inject random 2-digit number in the last word or middle
        num_str = str(secrets.randbelow(90) + 10)
        selected_words[-1] = f"{selected_words[-1]}{num_str}"

    return separator.join(selected_words)
