import datetime
import re
import os
from collections import defaultdict

import discord
from dotenv import load_dotenv

import UrlScan

# Clear terminal (compatible Windows et Linux/macOS)
os.system("cls" if os.name == "nt" else "clear")

load_dotenv()
DISCORD_TOKEN = os.getenv('DISCORD_TOKEN')

# ─── Intents ──────────────────────────────────────────────────────────────────
# Privileged intents à activer dans le Discord Developer Portal :
#   → Message Content Intent
#   → Server Members Intent
intents = discord.Intents.default()
intents.message_content = True
intents.members = True

client = discord.Client(intents=intents)

# ─── État global ──────────────────────────────────────────────────────────────
# Format : { 'guild_id': { 'log_channel', 'suspicion_role', 'suspicion_channel' } }
guild_dict: dict = {}

# Cache des messages récents par (guild_id, author_id), pour la détection de doublons.
# Format : { (guild_id, author_id): [{ 'content', 'timestamp' }] }
message_cache: dict = defaultdict(list)
CACHE_TTL_SECONDS = 120  # 2 minutes

# ─── Configuration ────────────────────────────────────────────────────────────
BLACKLISTED_KEYWORDS = [
    "disboard.org", "discord.gg", "discord.io", "discord.me",
    "discordlist.net", "discordservers.com", "discordsl.com",
    "discords.com", "discordapp.com/invite", "discord.com/invite"
]

IMAGE_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp', '.tiff', '.svg'}

REASON_LABELS = {
    "mention_everyone":     "Utilisation non autorisée de @everyone ou @here",
    "four_images":          "Envoi de 4 images simultanées (comportement suspect de compte compromis)",
    "blacklisted_link":     "Lien publicitaire ou d'invitation blacklisté",
    "external_channel_link":"Lien Discord pointant vers un serveur externe",
    "duplicate_link":       "Même lien posté en doublon (spam détecté)",
    "malicious_url":        "Lien malveillant détecté par VirusTotal",
}


# ─── Utilitaires ──────────────────────────────────────────────────────────────

def log(content: str):
    print(f"[LOG {datetime.datetime.now().strftime('%H:%M:%S')}] => {content}")


def has_role(user: discord.Member, role_id: int) -> bool:
    return any(role.id == role_id for role in user.roles)


def count_image_attachments(message: discord.Message) -> int:
    """Compte le nombre de pièces jointes de type image dans un message."""
    count = 0
    for attachment in message.attachments:
        if attachment.content_type and attachment.content_type.startswith("image/"):
            count += 1
        elif any(attachment.filename.lower().endswith(ext) for ext in IMAGE_EXTENSIONS):
            count += 1
    return count


def clean_cache(key: tuple):
    """Purge les entrées expirées du cache pour une clé donnée."""
    now = datetime.datetime.utcnow().timestamp()
    message_cache[key] = [
        entry for entry in message_cache[key]
        if now - entry['timestamp'] < CACHE_TTL_SECONDS
    ]


def is_duplicate(key: tuple, content: str) -> bool:
    """Retourne True si ce contenu a déjà été vu récemment pour cet utilisateur."""
    return any(entry['content'] == content for entry in message_cache[key])


def add_to_cache(message: discord.Message):
    key = (message.guild.id, message.author.id)
    clean_cache(key)
    message_cache[key].append({
        'content': message.content,
        'timestamp': message.created_at.timestamp()
    })


async def send_log(title: str, value: str, channel: discord.TextChannel):
    """Envoie un embed de log dans le channel dédié."""
    try:
        embed = discord.Embed(title="**📰 __AdProtect log__**", colour=0xffff00)
        embed.add_field(name=title, value=value[:1024])  # Limite Discord : 1024 chars
        embed.set_footer(text=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        await channel.send(embed=embed)
    except discord.Forbidden:
        log(f"Impossible d'envoyer un log dans #{channel.name} (permissions insuffisantes)")


# ─── Logique de modération ────────────────────────────────────────────────────

async def flag_message(message: discord.Message, reason: str):
    """
    Traite un message suspect :
      1. Supprime le message
      2. Attribue le rôle Suspicion à l'auteur
      3. Notifie dans le channel de suspicion (avec réactions ✅ / ❌ pour les admins)
      4. Envoie un log dans le channel de logs
    """
    guild_id = str(message.guild.id)
    log_channel       = guild_dict[guild_id]['log_channel']
    suspicion_role    = guild_dict[guild_id]['suspicion_role']
    suspicion_channel = guild_dict[guild_id]['suspicion_channel']
    reason_label      = REASON_LABELS.get(reason, reason)

    # 1. Suppression du message
    try:
        await message.delete()
    except discord.Forbidden:
        log(f"Impossible de supprimer le message de {message.author} (droits insuffisants)")
    except discord.NotFound:
        pass  # Déjà supprimé

    # 2. Attribution du rôle Suspicion
    try:
        await message.author.add_roles(suspicion_role)
    except discord.Forbidden:
        log(f"Impossible d'attribuer le rôle Suspicion à {message.author}")

    # 3. Notification dans le channel suspicion
    content_preview = message.content if message.content else "[aucun texte]"
    attachments_info = ""
    if message.attachments:
        filenames = ", ".join(a.filename for a in message.attachments)
        attachments_info = f"\n📎 **Pièces jointes ({len(message.attachments)}) :** {filenames}"

    suspicion_msg = await suspicion_channel.send(
        f"**:shield: __AdProtect__ :shield:**\n\n"
        f":warning: <@{message.author.id}>, vous avez été suspecté d'avoir envoyé un message non autorisé.\n\n"
        f"**Raison :** {reason_label}\n\n"
        f"Veuillez patienter qu'un **Administrateur** examine votre cas.\n"
        f"**Un ban définitif peut être prononcé si le message enfreint les règles.**\n\n"
        f"__Contenu du message :__\n```{content_preview[:900]}```"
        f"{attachments_info}"
    )
    await suspicion_msg.add_reaction("✅")
    await suspicion_msg.add_reaction("❌")

    # 4. Log
    await send_log(
        title=f"🚨 Détection — {reason_label}",
        value=(
            f"<@{message.author.id}> suspect dans <#{message.channel.id}>.\n"
            f"**Raison :** {reason_label}\n"
            f"```{content_preview[:400]}```"
        ),
        channel=log_channel
    )
    log(f"Message suspect de {message.author} ({reason}) traité.")


# ─── Initialisation du serveur ────────────────────────────────────────────────

async def create_suspicion_role(guild: discord.Guild, log_channel: discord.TextChannel) -> discord.Role:
    role = discord.utils.get(guild.roles, name="Suspicion")
    if role is None:
        role = await guild.create_role(name="Suspicion")
        await send_log(
            title="🆕 Rôle créé",
            value=f"Le rôle <@&{role.id}> a été créé automatiquement.",
            channel=log_channel
        )
    return role


async def create_channel(
    guild: discord.Guild,
    channel_name: str,
    overwrites: dict,
    log_channel: discord.TextChannel = None
) -> discord.TextChannel:
    channel = discord.utils.get(guild.channels, name=channel_name)
    if channel is None:
        position = log_channel.position + 1 if log_channel else 0
        channel = await guild.create_text_channel(
            channel_name, position=position, overwrites=overwrites
        )
        if log_channel:
            await send_log(
                title="🆕 Channel créé",
                value=f"Le channel <#{channel.id}> a été créé automatiquement.",
                channel=log_channel
            )
    return channel


async def load_all_prerequisites(guild: discord.Guild):
    """Crée (si absents) le rôle Suspicion et les channels dédiés au bot."""

    # Channel de logs (invisible à @everyone)
    log_channel = await create_channel(
        guild, "adprotect-logs",
        {guild.default_role: discord.PermissionOverwrite(view_channel=False)}
    )

    # Rôle Suspicion
    suspicion_role = await create_suspicion_role(guild, log_channel)

    # Channel suspicion (visible uniquement par le rôle Suspicion)
    suspicion_channel = await create_channel(
        guild, "adprotect-catched",
        {
            guild.default_role: discord.PermissionOverwrite(view_channel=False, send_messages=False),
            suspicion_role:     discord.PermissionOverwrite(view_channel=True, read_messages=True)
        },
        log_channel
    )

    # Masquer tous les channels au rôle Suspicion
    ignore_channels = {"adprotect-logs", "adprotect-catched"}
    for channel in guild.channels:
        if channel.name not in ignore_channels:
            await channel.set_permissions(suspicion_role, view_channel=False)

    return log_channel, suspicion_role, suspicion_channel


async def init_guild(guild: discord.Guild):
    log_channel, suspicion_role, suspicion_channel = await load_all_prerequisites(guild)
    guild_dict[str(guild.id)] = {
        "log_channel":       log_channel,
        "suspicion_role":    suspicion_role,
        "suspicion_channel": suspicion_channel
    }
    log(f"Serveur '{guild}' initialisé.")


# ─── Événements Discord ───────────────────────────────────────────────────────

@client.event
async def on_ready():
    global guild_dict
    log(f"AdProtect connecté sur {len(client.guilds)} serveur(s)")
    guild_dict = {}
    for guild in client.guilds:
        await init_guild(guild)
    log("Initialisation terminée. AdProtect est opérationnel ✅")


@client.event
async def on_guild_join(guild: discord.Guild):
    log(f"AdProtect a rejoint le serveur '{guild}' (id: {guild.id})")
    await init_guild(guild)


@client.event
async def on_message(message: discord.Message):
    # ── Pré-filtres ──────────────────────────────────────────────────────────
    if message.guild is None:
        return  # DM → ignorer
    if message.author.bot:
        return  # Bots → ignorer

    guild_id = str(message.guild.id)
    if guild_id not in guild_dict:
        return

    content       = message.content
    content_lower = content.lower()

    # ── Vérification 1 : @everyone / @here ───────────────────────────────────
    # mention_everyone = True si la mention a réussi (auteur avec permission).
    # La vérification sur le contenu brut couvre aussi les tentatives sans permission.
    if message.mention_everyone or "@everyone" in content or "@here" in content:
        await flag_message(message, "mention_everyone")
        return

    # ── Vérification 2 : Exactement 4 images ─────────────────────────────────
    if count_image_attachments(message) == 4:
        await flag_message(message, "four_images")
        return

    # ── Vérification 3 : Liens blacklistés ───────────────────────────────────
    if any(kw in content_lower for kw in BLACKLISTED_KEYWORDS):
        await flag_message(message, "blacklisted_link")
        return

    # ── Vérification 4 : Liens HTTP ──────────────────────────────────────────
    if "http" in content_lower:
        url_match = re.search(
            r"(https?|ftp)://[\w_-]+(?:\.[\w_-]+)+[\w.,@?^=%&:/~+#\-]*[\w@?^=%&/~+#\-]",
            content_lower
        )
        if url_match:
            link = url_match.group()

            # Lien Discord interne → autoriser si même serveur, bloquer sinon
            if "/channels/" in link:
                if str(message.guild.id) not in link:
                    await flag_message(message, "external_channel_link")
                return

            # Vérification doublon via cache mémoire
            cache_key = (message.guild.id, message.author.id)
            clean_cache(cache_key)
            if is_duplicate(cache_key, content):
                add_to_cache(message)
                await flag_message(message, "duplicate_link")
                return
            add_to_cache(message)

            # Scan VirusTotal (asynchrone — ne bloque pas l'event loop)
            if await UrlScan.scan_url(link):
                await flag_message(message, "malicious_url")
                return

            # Lien considéré sûr → simple log informatif
            await send_log(
                title="⚠ Lien publié",
                value=(
                    f"Lien publié dans <#{message.channel.id}> par <@{message.author.id}>.\n"
                    f"[→ Voir le message](https://discord.com/channels/"
                    f"{message.guild.id}/{message.channel.id}/{message.id})\n"
                    f"```{content[:400]}```"
                ),
                channel=guild_dict[guild_id]['log_channel']
            )


@client.event
async def on_reaction_add(reaction: discord.Reaction, user: discord.Member):
    # ── Pré-filtres ──────────────────────────────────────────────────────────
    if user.bot:
        return

    guild_id = str(user.guild.id)
    if guild_id not in guild_dict:
        return

    suspicion_channel = guild_dict[guild_id]['suspicion_channel']
    suspicion_role    = guild_dict[guild_id]['suspicion_role']
    log_channel       = guild_dict[guild_id]['log_channel']

    # Traiter uniquement les réactions dans le channel suspicion
    if reaction.message.channel.id != suspicion_channel.id:
        return

    # Supprimer immédiatement la réaction (nettoyage visuel)
    try:
        await reaction.remove(user)
    except discord.Forbidden:
        pass

    # Ignorer les réactions parasites (ni ✅ ni ❌)
    if str(reaction.emoji) not in ("✅", "❌"):
        return

    # Un utilisateur en suspicion ne peut pas modérer
    if has_role(user, suspicion_role.id):
        return

    # Extraire l'ID du suspect depuis la première mention @user du message
    mention_match = re.search(r"<@!?(\d+)>", reaction.message.content)
    if not mention_match:
        log("Impossible d'extraire l'ID du suspect depuis le message de suspicion.")
        return

    suspect_uid = int(mention_match.group(1))
    try:
        suspect_user = await user.guild.fetch_member(suspect_uid)
    except discord.NotFound:
        log(f"Membre {suspect_uid} introuvable (a peut-être quitté le serveur).")
        await reaction.message.delete()
        return

    await reaction.message.delete()

    if str(reaction.emoji) == "✅":
        # Innocenter : retirer le rôle Suspicion
        await suspect_user.remove_roles(suspicion_role)
        await send_log(
            title="✅ Membre innocenté",
            value=(
                f"<@{user.id}> a jugé (✅) que le message de <@{suspect_user.id}> "
                f"n'était pas malveillant.\n"
                f"<@{suspect_user.id}> retrouve ses droits sur le serveur."
            ),
            channel=log_channel
        )
        log(f"{suspect_user} innocenté par {user}.")

    elif str(reaction.emoji) == "❌":
        # Bannir définitivement
        try:
            await suspect_user.send(
                f"**Vous avez été banni du serveur « {user.guild} » pour la raison suivante :**\n"
                f"Publication de contenu publicitaire, malveillant ou comportement suspect."
            )
        except discord.Forbidden:
            pass  # DMs désactivés par l'utilisateur
        await suspect_user.ban(reason="Publicité, Phishing ou comportement suspect — AdProtect")
        await send_log(
            title="❌ Membre banni",
            value=(
                f"<@{user.id}> a jugé (❌) que le message de <@{suspect_user.id}> "
                f"était malveillant.\n"
                f"<@{suspect_user.id}> a été banni définitivement."
            ),
            channel=log_channel
        )
        log(f"{suspect_user} banni par {user}.")


client.run(DISCORD_TOKEN)

