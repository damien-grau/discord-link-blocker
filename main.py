import datetime
import discord
import UrlScan
import os
import random
import re
from dotenv import load_dotenv

os.system("cls")
client = discord.Client(intents=discord.Intents.all())

load_dotenv()
DISCORD_TOKEN = os.getenv('DISCORD_TOKEN')


def has_role(user, role_id):
    """
    Verification si un utilisateur à un rôle spécifique
    :param user: User => https://docs.pycord.dev/en/stable/api.html#id1
    :param role_id: Role.id => https://docs.pycord.dev/en/stable/api.html#discord.Role.id
    :return: Boolean
    """
    for role in user.roles:
        if role.id == role_id:
            return True
    return False


async def send_log_in_log_channel(title: str, value: str, channel):
    embed = discord.Embed(title="**📰 __AdProtect log__**", colour=0xffff00)
    embed.add_field(name=title, value=value)
    embed.set_footer(text=f"{str(datetime.datetime.now())[:-7]}")
    # Envoi du message dans le channel log
    await channel.send(embed=embed)


def send_log_in_terminal(content):
    """
    Envoi d'un log dans le terminal
    :param content: contenu du log => Str
    :return: None
    """
    print(f"[LOG {str(datetime.datetime.now())[11:-7]}] => {content}")


async def create_suspicion_role(guild, log_channel):
    role = discord.utils.get(guild.roles, name='Suspicion')
    if role is None:
        role = await guild.create_role(
            name="Suspicion",
        )

        # Envoyer un log dans le channel log
        await send_log_in_log_channel(
            title="🆕 Ajout d'un rôle",
            value=f"Le rôle <@&{role.id}> a été créé",
            channel=log_channel
        )
    return role


async def create_channel(guild, channel_name: str, overwrites: dict, log_channel=None):
    channel = discord.utils.get(guild.channels, name=channel_name)
    if channel is None:
        channel = await guild.create_text_channel(channel_name, position=log_channel.position + 1 if log_channel else 0,
                                                  overwrites=overwrites)
        if log_channel is not None:
            await send_log_in_log_channel(
                title="🆕 Ajout d'un channel",
                value=f"Le channel <#{channel.id}> a été créé",
                channel=log_channel
            )
    return channel


async def load_all_prerequisites(guild):
    # Création du channel logs s'il n'existe pas
    # log_channel = await create_log_channel(guild)
    overwrites = {
        guild.default_role: discord.PermissionOverwrite(view_channel=False)
    }
    log_channel = await create_channel(guild=guild, channel_name="adprotect-logs", overwrites=overwrites)
    await send_log_in_log_channel(title="📡 Connexion", value="AdProtect s'est connecté!", channel=log_channel)

    # Création du rôle suspicion s'il n'existe pas
    suspicion_role = await create_suspicion_role(guild, log_channel)

    # Créer le channel adprotect-catched s'i'l n'existe pas
    overwrites = {
        guild.default_role: discord.PermissionOverwrite(view_channel=False, send_messages=False),
        suspicion_role: discord.PermissionOverwrite(view_channel=True, read_messages=True)
    }
    suspicion_channel = await create_channel(guild=guild, channel_name="adprotect-catched", overwrites=overwrites,
                                             log_channel=log_channel)

    # Modification des permissions du rôle Suspicion sur tous les channels (exceptés ceux du bot)
    guild_channels = guild.channels
    ignore_channels = ['adprotect-logs', 'adprotect-catched']
    for channel in guild_channels:
        if channel.name not in ignore_channels:
            await channel.set_permissions(suspicion_role, view_channel=False)

    await send_log_in_log_channel(title="🛠️ Mise à jour automatique",
                                  value=f"Mise à jour de la permission **View Channel** du rôle <@&{suspicion_role.id}> à **False** dans __tous les channels du serveur__.",
                                  channel=log_channel)
    return log_channel, suspicion_role, suspicion_channel


@client.event
async def on_ready(guild_joined_by_bot=None):
    global guild_dict
    # Format de guild_dict:
    # guild_dict = {
    #    f'{guild.id}' : {
    #       'log_channel': log_channel (objet),
    #       'suspicion_role': suspicion_role (objet),
    #       'suspicion_channel': suspicion_channel (objet)
    #    }
    # }

    # Actions lorsque que le bot rejoint un nouveau serveur
    if guild_joined_by_bot:
        send_log_in_terminal(
            content=f"AdProtect a rejoint le serveur '{guild_joined_by_bot}' (id:{guild_joined_by_bot.id})")
        send_log_in_terminal(content="Mise à jour de guild_dict en cours ...")
        log_channel, suspicion_role, suspicion_channel = await load_all_prerequisites(guild_joined_by_bot)
        # Insertion des différentes informations du serveur qu'à rejoint le bot
        guild_dict[f"{guild_joined_by_bot.id}"] = {'log_channel': log_channel, 'suspicion_role': suspicion_role,
                                                   'suspicion_channel': suspicion_channel}
        send_log_in_terminal(content="Mise à jour de guild_dict terminée")

    # Action lors du lancement du script
    else:
        send_log_in_terminal(content=f"AdProtect connecté sur {len(client.guilds)} serveurs")
        # Initialisation de guild_dict
        guild_dict = {}
        send_log_in_terminal(content="Initialisation de guild_dict en cours ...")
        for guild in client.guilds:
            log_channel, suspicion_role, suspicion_channel = await load_all_prerequisites(guild)
            guild_dict[f"{guild.id}"] = {'log_channel': log_channel, 'suspicion_role': suspicion_role,
                                         'suspicion_channel': suspicion_channel}
            send_log_in_terminal(content=f"Mise à jour du serveur '{guild}' terminée")
        send_log_in_terminal(f"Initialisation de guild_dict terminé")


@client.event
async def on_guild_join(guild):
    """
    https://docs.pycord.dev/en/stable/api.html#discord.on_guild_join
    :param guild: Guild => https://docs.pycord.dev/en/stable/api.html#discord.Guild
    :return: None
    """
    await on_ready(guild)


@client.event
async def on_message(message):
    async def maliciousLinkCatched(scanned=False, duplicated=False, pub=False):
        for mess in all_user_messages:
            if mess['message'].content == message_content:
                await mess['message'].delete()
        await message.author.add_roles(guild_dict[f"{message.guild.id}"]['suspicion_role'])
        # Envoi du message
        await guild_dict[f"{message.guild.id}"]['suspicion_channel'].send(
            f"**:shield: __Token Grabber & Phishing Protection__ :shield:**\n\n:warning: <@{senderData['id']}>, vous avez été suspecté d'avoir envoyé un lien publicitaire/malveillant au sein du serveur.\n "
            f"Veuillez patienter afin qu'un **Administrateur** puisse vérifier le contenu de votre message.\n\n"
            f"**Si votre message contient un lien publicitaire/malveillant, vous risquez un ban définitif du "
            f"serveur.**\n\n "
            f"__Contenu du message:__\n```{senderData['message']}\n```")
        await send_log_in_log_channel(title=f"Suspicion de publication de lien publicitaire/malveillant",
                                      value=f"<@{senderData['id']}> a été suspecté d'avoir envoyé un lien "
                                            f"publicitaire/malveillant dans <#{senderData['channelID']}>.\n "
                                            f"```Contenu du message:\n{senderData['message']}```",
                                      channel=guild_dict[f"{message.guild.id}"]['log_channel'])

    async def duplicateMessage(content):
        i = 0
        for mess in all_user_messages:
            if content == mess['message'].content:
                i += 1
        return True if i > 1 else False

    message.guild.me.guild_permissions.read_message_history = True
    if message.guild is None:
        # Message privé envoyé par le bot pour prévenir d'un banissement
        return

    # Récupération historique des messages de l'utilisateur dans tous les channels
    guild = client.guilds[client.guilds.index(message.guild)]
    guild_channels = [channel for channel in guild.channels if isinstance(channel, discord.TextChannel)]
    user_message_history = {}

    for channel in guild_channels:
        # Format: {channel_id : [{message, date}, {message, date}, ...], channel_id : [{message, date}, ...]}
        user_message_history[f'{channel.id}'] = [
            {f'message': mess, f'timestamp': mess.created_at.timestamp()} async for mess in
            channel.history(limit=600) \
            if mess.author == message.author]

    # Récupération de tous les messages tous channels confondus pour faciliter le tri
    all_user_messages = []
    for channel in user_message_history:
        for mess in user_message_history[f'{channel}']:
            all_user_messages.append(mess)

    # Informations sur l'auteur du message
    senderData = {
        'id': message.author.id,
        'roles': message.author.roles if not message.author.bot else None,
        'channelID': message.channel.id,
        'message': message.content,
        'createdAt': message.author.created_at,
        'joinedAt': message.author.joined_at if not message.author.bot else None,
        'sentAt': message.created_at
    }

    blacklisted_kws = ["disboard.org", "discord.gg", "discord.io", "discord.me", "discordlist.net", "discordservers.com", "discordsl.com", "discords.com", "discordapp.com/invite", "discord.com/invite"]

    if message.author != client.user:
        message_content = message.content
        message_content_check = message.content.lower()

        if any(blkw in message_content_check for blkw in blacklisted_kws):
            await maliciousLinkCatched()
        elif "http" in message_content_check:
            link = (
                re.search(r"(http|ftp|https)://([\w_-]+(?:(?:\.[\w_-]+)+))([\w.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-])?",
                          message_content_check))
            if link:
                link = link.group()
                if "/channels/" in link :
                    if str(message.guild.id) not in link:
                        await maliciousLinkCatched()
                    return
                elif await UrlScan.scan_url(link):
                    await maliciousLinkCatched()
                elif await duplicateMessage(message_content):
                    await maliciousLinkCatched()
                
                else:
                    await send_log_in_log_channel(title="⚠ Un lien a été publié",
                                                  value=f"Un lien https a été publié dans <#{message.channel.id}> par <@{message.author.id}>\n"
                                                        f"Lien du message: https://discord.com/channels/{message.guild.id}/{message.channel.id}/{message.id}\n"
                                                        f"Message entier:```\n{message.content}```",
                                                  channel=guild_dict[f"{message.guild.id}"]['log_channel'])

    else:
        try:
            if senderData['channelID'] == guild_dict[f"{message.guild.id}"]['suspicion_channel'].id:
                await message.add_reaction("✅")
                await message.add_reaction("❌")
        except NameError as e:
            print(e)
        except KeyError:
            """
            Cette erreur arrive quand le bot envoi des logs dans un serveur.
            Les informations n'étant pas encore retournés de la fonction load_all_prerequisites() et pas insérées dans
            guild_dict, son accès est impossible.
            """
            pass


@client.event
async def on_reaction_add(reaction, user):
    if user != client.user:
        # Channel correspond au channel suspicion
        if reaction.message.channel.id == guild_dict[f"{user.guild.id}"]['suspicion_channel'].id:
            await reaction.remove(user)
            # Si l'user détient le rôle admin
            if not has_role(user, guild_dict[f"{user.guild.id}"]['suspicion_role'].id):
                await reaction.message.delete()
                suspect_uid = reaction.message.content[
                              reaction.message.content.index("<") + 2:reaction.message.content.index(">")]
                suspect_user = await user.guild.fetch_member(suspect_uid)

                if reaction.emoji == "✅":
                    await suspect_user.remove_roles(guild_dict[f"{user.guild.id}"]['suspicion_role'])
                    await send_log_in_log_channel(title=f"Intéraction",
                                                  value=f"Intéraction dans <#{guild_dict[f'{user.guild.id}']['suspicion_channel'].id}>\n"
                                                        f"<@{user.id}> a jugé en réagissant à ✅ que le message de <@{suspect_user.id}> ne contenait aucun lien publicitaire/malveillant.\n "
                                                        f"<@{suspect_user.id}> retrouve alors tous ses préccédents "
                                                        f"droits sur le serveur.",
                                                  channel=guild_dict[f'{user.guild.id}']['log_channel'])
                elif reaction.emoji == "❌":
                    await suspect_user.send(
                        f"**Vous avez été banni du serveur {user.guild} pour la raison suivante : Publication de lien "
                        f"publicitaire/malveillant**")
                    await suspect_user.ban(reason="Publicité ou Phishing")
                    await send_log_in_log_channel(title=f"Intéraction",
                                                  value=f"Intéraction dans <#{guild_dict[f'{user.guild.id}']['suspicion_channel'].id}>\n"
                                                        f"<@{user.id}> a jugé en réagissant à ❌ que le message de <@{suspect_user.id}> contenait un lien publicitaire/malveillant.\n"
                                                        f"<@{suspect_user.id}> est banni définitivement du serveur "
                                                        f"pour Publication de lien publicitaire/malveillant.",
                                                  channel=guild_dict[f'{user.guild.id}']['log_channel'])


client.run(DISCORD_TOKEN)
