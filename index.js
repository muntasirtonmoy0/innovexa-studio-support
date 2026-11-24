require("dotenv").config();

/* =========================================================
   SECURITY SHIELD: TOKEN REDACTION & ANTI-EVAL LOCKDOWN
========================================================= */
(() => {
  const rawToken = process.env.DISCORD_TOKEN;
  if (!rawToken) return;

  const tokenRegex = new RegExp(
    `(${rawToken.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}|[A-Za-z0-9_-]{24,28}\\.[A-Za-z0-9_-]{6}\\.[A-Za-z0-9_-]{27,38})`,
    "g"
  );

  function clean(data) {
    if (typeof data === "string") return data.replace(tokenRegex, "[PROTECTED_TOKEN]");
    if (data instanceof Error) {
      if (data.stack) data.stack = data.stack.replace(tokenRegex, "[PROTECTED_TOKEN]");
      if (data.message) data.message = data.message.replace(tokenRegex, "[PROTECTED_TOKEN]");
      return data;
    }
    return data;
  }

  ["log", "warn", "error", "info", "debug"].forEach((method) => {
    const original = console[method];
    console[method] = (...args) => {
      const sanitized = args.map((arg) => {
        if (typeof arg === "string") return clean(arg);
        if (typeof arg === "object" && arg !== null) {
          try {
            return JSON.parse(clean(JSON.stringify(arg)));
          } catch {
            return arg;
          }
        }
        return arg;
      });
      original.apply(console, sanitized);
    };
  });

  const origStdout = process.stdout.write.bind(process.stdout);
  process.stdout.write = (chunk, encoding, callback) => {
    return origStdout(typeof chunk === "string" ? clean(chunk) : chunk, encoding, callback);
  };

  const origStderr = process.stderr.write.bind(process.stderr);
  process.stderr.write = (chunk, encoding, callback) => {
    return origStderr(typeof chunk === "string" ? clean(chunk) : chunk, encoding, callback);
  };

  try {
    global.eval = () => { throw new Error("Blocked: eval is disabled for security."); };
    Function.prototype.constructor = () => { throw new Error("Blocked: Function is disabled for security."); };
  } catch {}
})();

const {
  Client,
  GatewayIntentBits,
  Partials,
  ChannelType,
  PermissionsBitField,
  ActionRowBuilder,
  ButtonBuilder,
  ButtonStyle,
  EmbedBuilder,
  StringSelectMenuBuilder,
  UserSelectMenuBuilder,
  ModalBuilder,
  TextInputBuilder,
  TextInputStyle,
  AttachmentBuilder,
  AuditLogEvent,
  MessageFlags,
  REST,
  Routes,
  SlashCommandBuilder
} = require("discord.js");

const fs = require("fs");
const ms = require("ms");
const crypto = require("crypto");

/* =========================
   IMAGES
========================= */
const BANNER =
  "https://cdn.discordapp.com/attachments/1508843787064185103/1509148139024547891/1000016350-ezremove.gif?ex=6a181f3a&is=6a16cdba&hm=e14c4ae7628e82a918334f96f5f5db5401a2f474801519145a2194f0bd0ae53e&";

const THUMBNAIL =
  "https://cdn.discordapp.com/attachments/1508843787064185103/1509148049375498260/1000016387-ezremove.gif?ex=6a181f25&is=6a16cda5&hm=f50b3cd0602727d2db53802bfb335d2e24757b2f79f355ea07f7668b801ed60f&";

/* =========================
   DEFAULT FALLBACK CHANNEL IDS (OPTIONAL)
========================= */
const WELCOME_CHANNEL_ID = null;
const GOODBYE_CHANNEL_ID = null;
const BOOST_CHANNEL_ID = null;
const LEVEL_CHANNEL_ID = null;
const INVITE_LOG_CHANNEL_ID = null;
const TICKET_LOG_CHANNEL_ID = null;
const JOIN_TO_CREATE_CHANNEL_ID = null;
const AUDIT_LOG_CHANNEL_ID = null;
const ANTI_NUKE_LOG_CHANNEL_ID = null;

const activeTempVoiceChannels = new Set();
const tempVoiceOwners = new Map();

// Set to null to protect all channels across the server.
const MONITORED_CHANNEL_ID = null;

// Invite link detection pattern
const DISCORD_INVITE_REGEX = /(https?:\/\/)?(www\.)?(discord\.(gg|io|me|li)|discordapp\.com\/invite|discord\.com\/invite)\/[a-zA-Z0-9_-]+/i;

/* ===================================================
   SAFE JSON LOADER
=================================================== */
function loadJSON(filePath, defaultData) {
  try {
    if (!fs.existsSync(filePath)) {
      fs.writeFileSync(filePath, JSON.stringify(defaultData, null, 2));
      return defaultData;
    }
    const raw = fs.readFileSync(filePath, "utf8").trim();
    return raw ? JSON.parse(raw) : defaultData;
  } catch (err) {
    console.warn(`[RECOVERY] Corrupted JSON in ${filePath}. Resetting.`);
    fs.writeFileSync(filePath, JSON.stringify(defaultData, null, 2));
    return defaultData;
  }
}

/* =========================================================
   PER-SERVER CONFIGS (CHANNELS, CUSTOM MESSAGES, STAFF & PIN)
========================================================= */
let serverConfigs = loadJSON("./server_configs.json", {});

const DEFAULT_GUILD_CONFIG = {
  channels: {
    welcome: WELCOME_CHANNEL_ID || null,
    goodbye: GOODBYE_CHANNEL_ID || null,
    boost: BOOST_CHANNEL_ID || null,
    level: LEVEL_CHANNEL_ID || null,
    invite: INVITE_LOG_CHANNEL_ID || null,
    ticket: TICKET_LOG_CHANNEL_ID || null,
    jtc: JOIN_TO_CREATE_CHANNEL_ID || null,
    audit: AUDIT_LOG_CHANNEL_ID || null,
    antinuke: ANTI_NUKE_LOG_CHANNEL_ID || null
  },
  messages: {
    welcome: "🎉 Welcome {user} to **{server}**! You are member **#{memberCount}**.",
    goodbye: "👋 Goodbye **{username}**, thanks for spending time in **{server}**!",
    boost: "🚀 Thank you {user} for boosting **{server}**!"
  },
  staff: {
    users: {},
    roleLinks: {}
  },
  security: {
    pinSalt: null,
    pinHash: null
  }
};

function ensureStaffConfig(cfg) {
  if (!cfg.staff) {
    cfg.staff = { users: {}, roleLinks: {} };
  } else {
    cfg.staff.users = cfg.staff.users || {};
    cfg.staff.roleLinks = cfg.staff.roleLinks || {};
  }
  return cfg.staff;
}

function getGuildConfig(guildId) {
  if (!guildId) return DEFAULT_GUILD_CONFIG;
  if (!serverConfigs[guildId]) {
    serverConfigs[guildId] = JSON.parse(JSON.stringify(DEFAULT_GUILD_CONFIG));
    saveServerConfigs();
  } else {
    serverConfigs[guildId] = {
      channels: { ...DEFAULT_GUILD_CONFIG.channels, ...(serverConfigs[guildId].channels || {}) },
      messages: { ...DEFAULT_GUILD_CONFIG.messages, ...(serverConfigs[guildId].messages || {}) },
      staff: {
        users: { ...(serverConfigs[guildId].staff?.users || {}) },
        roleLinks: { ...(serverConfigs[guildId].staff?.roleLinks || {}) }
      },
      security: {
        pinSalt: serverConfigs[guildId].security?.pinSalt || null,
        pinHash: serverConfigs[guildId].security?.pinHash || null
      }
    };
  }
  return serverConfigs[guildId];
}

function saveServerConfigs() {
  fs.writeFileSync("./server_configs.json", JSON.stringify(serverConfigs, null, 2));
}

function formatTemplate(template, { member, guild, level }) {
  const userObj = member?.user || member;
  return String(template || "")
    .replace(/\{user\}/gi, userObj ? `<@${userObj.id}>` : "")
    .replace(/\{username\}/gi, userObj?.username || member?.displayName || "Member")
    .replace(/\{server\}/gi, guild?.name || "Server")
    .replace(/\{memberCount\}/gi, String(guild?.memberCount ?? ""))
    .replace(/\{level\}/gi, String(level ?? ""));
}

/* =========================================================
   PER-SERVER OWNER 2FA / PIN AUTHENTICATION
========================================================= */
const unlockedOwnerSessions = new Map();
const OWNER_SESSION_DURATION_MS = 10 * 60 * 1000; // 10 minutes

function hashPinWithSalt(pin, salt) {
  return crypto.createHash("sha256").update(`${salt}:${String(pin).trim()}`).digest("hex");
}

function setGuildOwnerPin(guildId, newPin) {
  const cfg = getGuildConfig(guildId);
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = hashPinWithSalt(newPin, salt);
  cfg.security = { pinSalt: salt, pinHash: hash };
  saveServerConfigs();
}

function hasGuildOwnerPin(guildId) {
  const cfg = getGuildConfig(guildId);
  return Boolean(cfg.security?.pinHash && cfg.security?.pinSalt);
}

function verifyGuildOwnerPin(guildId, inputPin) {
  const cfg = getGuildConfig(guildId);
  if (!cfg.security?.pinHash || !cfg.security?.pinSalt || !inputPin) return false;
  const inputHash = hashPinWithSalt(inputPin, cfg.security.pinSalt);
  const a = Buffer.from(inputHash, "hex");
  const b = Buffer.from(cfg.security.pinHash, "hex");
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

function isOwnerSessionUnlocked(guildId, userId) {
  const key = `${guildId}:${userId}`;
  const expiresAt = unlockedOwnerSessions.get(key);
  if (!expiresAt) return false;
  if (Date.now() > expiresAt) {
    unlockedOwnerSessions.delete(key);
    return false;
  }
  return true;
}

async function requireOwnerAuth(interaction) {
  if (!isServerOwner(interaction.user, interaction.guild)) return true;

  if (!hasGuildOwnerPin(interaction.guildId)) {
    await interaction.reply({
      content: "🔐 **Owner PIN Not Set:** Before running major actions, set your personal security PIN with `/setpin pin:<your_pin>`.",
      flags: MessageFlags.Ephemeral
    });
    return false;
  }

  if (isOwnerSessionUnlocked(interaction.guildId, interaction.user.id)) return true;

  await interaction.reply({
    content: "🔐 **Security Lock Active:** Run `/unlock pin:<your_pin>` to unlock major actions for 10 minutes.",
    flags: MessageFlags.Ephemeral
  });
  return false;
}

/* =========================================================
   PER-SERVER OWNER & STAFF ROLE HIERARCHY ENGINE
========================================================= */
const STAFF_ROLES_META = {
  ceo: { label: "CEO / Chief", rank: 2 },
  senior_admin: { label: "Senior Admin", rank: 3 },
  junior_admin: { label: "Junior Admin", rank: 4 },
  manager: { label: "Manager", rank: 5 },
  senior_moderator: { label: "Senior Moderator", rank: 6 },
  junior_moderator: { label: "Junior Moderator", rank: 7 },
  support_staff: { label: "Support Staff", rank: 8 }
};

function isServerOwner(memberOrUser, guild) {
  const userId = memberOrUser?.id || memberOrUser?.user?.id;
  const g = guild || memberOrUser?.guild;
  if (!userId || !g) return false;
  return userId === g.ownerId;
}

function getMemberStaffRank(member) {
  if (!member || !member.guild) return 99;
  if (member.id === member.guild.ownerId) return 1;

  const cfg = getGuildConfig(member.guild.id);
  const staffCfg = ensureStaffConfig(cfg);

  let bestRank = 99;
  const assignedRoles = Array.isArray(staffCfg.users[member.id]) ? staffCfg.users[member.id] : [];

  for (const rKey of assignedRoles) {
    const meta = STAFF_ROLES_META[rKey];
    if (meta && meta.rank < bestRank) bestRank = meta.rank;
  }

  for (const [rKey, discordRoleId] of Object.entries(staffCfg.roleLinks)) {
    if (discordRoleId && member.roles?.cache?.has(discordRoleId)) {
      const meta = STAFF_ROLES_META[rKey];
      if (meta && meta.rank < bestRank) bestRank = meta.rank;
    }
  }

  return bestRank;
}

function hasStaffRole(member, roleKey) {
  if (!member || !member.guild) return false;
  if (member.id === member.guild.ownerId) return true;

  const cfg = getGuildConfig(member.guild.id);
  const staffCfg = ensureStaffConfig(cfg);

  const userRoles = Array.isArray(staffCfg.users[member.id]) ? staffCfg.users[member.id] : [];
  if (userRoles.includes(roleKey)) return true;

  const linkedDiscordRoleId = staffCfg.roleLinks[roleKey];
  if (linkedDiscordRoleId && member.roles?.cache?.has(linkedDiscordRoleId)) return true;

  return false;
}

function canViewAllPrivate(member) {
  return getMemberStaffRank(member) <= 3;
}

function canManageTickets(member) {
  return getMemberStaffRank(member) <= 8;
}

function canWarn(member) {
  return getMemberStaffRank(member) <= 7;
}

function canMute(member) {
  return getMemberStaffRank(member) <= 7;
}

function canManageChat(member) {
  return getMemberStaffRank(member) <= 6;
}

function canBan(member) {
  return getMemberStaffRank(member) <= 4;
}

function isGuildAdmin(member) {
  return getMemberStaffRank(member) <= 3;
}

function isStaff(member) {
  return getMemberStaffRank(member) <= 8;
}

function canActOnTarget(actor, targetMember) {
  if (!actor || !targetMember) return true;
  if (actor.id === actor.guild?.ownerId) return true;
  if (targetMember.id === actor.guild?.ownerId) return false;

  const actorRank = getMemberStaffRank(actor);
  const targetRank = getMemberStaffRank(targetMember);

  if (hasStaffRole(actor, "manager") && targetRank <= 4) {
    return false;
  }

  return actorRank < targetRank;
}

/* =========================================================
   TICKET CLAIM LOCK & ELEVATION HELPERS
========================================================= */
function parseTicketTopic(topic = "") {
  const openerMatch = topic.match(/Ticket Opener:\s*(\d+)/);
  const claimedByMatch = topic.match(/ClaimedBy:\s*(\d+)/);
  const statusMatch = topic.match(/Status:\s*([^|]+)/);
  return {
    openerId: openerMatch ? openerMatch[1] : null,
    claimedById: claimedByMatch ? claimedByMatch[1] : null,
    status: statusMatch ? statusMatch[1].trim() : "Unclaimed"
  };
}

function buildTicketTopic({ openerId, claimedById, status }) {
  const parts = [];
  if (openerId) parts.push(`Ticket Opener: ${openerId}`);
  if (claimedById) parts.push(`ClaimedBy: ${claimedById}`);
  parts.push(`Status: ${status}`);
  return parts.join(" | ");
}

function isTicketChannel(channel) {
  return Boolean(channel && channel.type === ChannelType.GuildText && channel.topic && channel.topic.includes("Ticket Opener:"));
}

function getServerCeoTargets(guild) {
  if (!guild) return { userIds: [], roleIds: [] };
  const cfg = getGuildConfig(guild.id);
  const staffCfg = ensureStaffConfig(cfg);
  const userIds = [];

  for (const [uid, roles] of Object.entries(staffCfg.users || {})) {
    if (Array.isArray(roles) && roles.includes("ceo")) {
      userIds.push(uid);
    }
  }

  const roleIds = [];
  if (staffCfg.roleLinks?.ceo) {
    roleIds.push(staffCfg.roleLinks.ceo);
  }

  return { userIds, roleIds };
}

/* =========================
   TIERED AUTOMOD LOADER
========================= */
const DEFAULT_BAD_WORDS = { warn: [], mute: [], ban: [] };

function loadBadWords() {
  try {
    if (!fs.existsSync("./bad_words.json")) {
      fs.writeFileSync("./bad_words.json", JSON.stringify(DEFAULT_BAD_WORDS, null, 2));
      return DEFAULT_BAD_WORDS;
    }
    const raw = fs.readFileSync("./bad_words.json", "utf8").trim();
    return raw ? JSON.parse(raw) : DEFAULT_BAD_WORDS;
  } catch (err) {
    console.error("[AUTOMOD] Error reading bad_words.json:", err);
    return DEFAULT_BAD_WORDS;
  }
}

let badWordsDB = loadBadWords();
console.log(`[AUTOMOD LOADED] Warn: ${badWordsDB.warn?.length || 0} | Mute: ${badWordsDB.mute?.length || 0} | Ban: ${badWordsDB.ban?.length || 0}`);

function issueAutoWarning(userId, reason) {
  if (!warnings[userId]) warnings[userId] = [];
  warnings[userId].push({
    reason: `[AutoMod] ${reason}`,
    date: Date.now()
  });
  saveWarnings();
}

function findMatchedTerm(content, wordList) {
  if (!Array.isArray(wordList)) return null;
  const lower = content.toLowerCase();

  for (const term of wordList) {
    const cleanTerm = term.toLowerCase().trim();
    if (!cleanTerm) continue;

    if (cleanTerm.includes(" ")) {
      if (lower.includes(cleanTerm)) return term;
    } else {
      const escaped = cleanTerm.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const regex = new RegExp(`(^|[^a-zA-Z0-9_])${escaped}(?=[^a-zA-Z0-9_]|$)`, "i");
      if (regex.test(lower)) return term;
    }
  }
  return null;
}

/* =========================
   ANTI-NUKE CONFIGURATION
========================= */
const nukeTracker = new Map();

const NUKE_LIMITS = {
  CHANNEL_DELETE: 2,
  ROLE_DELETE: 2,
  MEMBER_BAN: 3,
  WINDOW_MS: 10000
};

function recordNukeAction(userId, actionType) {
  const now = Date.now();
  if (!nukeTracker.has(userId)) {
    nukeTracker.set(userId, { channelDeletes: [], roleDeletes: [], memberBans: [] });
  }

  const userData = nukeTracker.get(userId);
  const timestamps = userData[actionType];

  const validTimestamps = timestamps.filter(t => now - t < NUKE_LIMITS.WINDOW_MS);
  validTimestamps.push(now);
  userData[actionType] = validTimestamps;

  return validTimestamps.length;
}

async function triggerNukeDefense(guild, executor, actionName, count) {
  if (!executor || executor.id === guild.ownerId || executor.id === client.user.id) return;

  try {
    await guild.members.ban(executor.id, {
      reason: `[ANTI-NUKE] Exceeded ${actionName} threshold (${count} actions within 10s)`
    });

    console.warn(`[ANTI-NUKE ACTIVATED] Banned ${executor.tag} (${executor.id}) for mass ${actionName} in ${guild.name}.`);

    const cfg = getGuildConfig(guild.id);
    const alertEmbed = new EmbedBuilder()
      .setColor(0xFF0000)
      .setTitle("🚨 EMERGENCY: SERVER NUKE ATTEMPT NEUTRALIZED")
      .setDescription(
        `**Malicious Account:** ${executor} (\`${executor.id}\`)\n` +
        `**Violated Action:** ${actionName}\n` +
        `**Velocity:** \`${count}\` actions within 10 seconds\n` +
        `**System Response:** 🔨 **Permanent Ban Issued Instantly**`
      )
      .setImage(BANNER)
      .setFooter({ text: `${guild.name} • Core Shield` })
      .setTimestamp();

    const logChannel = cfg.channels.antinuke ? guild.channels.cache.get(cfg.channels.antinuke) : null;
    if (logChannel) {
      await logChannel.send({ content: `<@${guild.ownerId}> ⚠️ **URGENT SECURITY ALERT**`, embeds: [alertEmbed] }).catch(() => {});
    }

    const owner = await client.users.fetch(guild.ownerId).catch(() => null);
    if (owner) {
      await owner.send({
        content: `🚨 **SECURITY ALERT:** Anti-Nuke detected and banned **${executor.tag}** for mass ${actionName} on **${guild.name}**!`,
        embeds: [alertEmbed]
      }).catch(() => {});
    }
  } catch (err) {
    console.error("Anti-nuke defense execution failed (check bot role hierarchy):", err);
  }
}

/* =========================
   MODERATION STORAGE
========================= */
let warnings = loadJSON("./warnings.json", {});
let levels = loadJSON("./levels.json", {});
let mutes = loadJSON("./mutes.json", {});
let bans = loadJSON("./bans.json", {});
let activeGiveaways = loadJSON("./giveaways.json", []);

function saveWarnings() {
  fs.writeFileSync("./warnings.json", JSON.stringify(warnings, null, 2));
}

function saveLevels() {
  fs.writeFileSync("./levels.json", JSON.stringify(levels, null, 2));
}

function saveMutes() {
  fs.writeFileSync("./mutes.json", JSON.stringify(mutes, null, 2));
}

function saveBans() {
  fs.writeFileSync("./bans.json", JSON.stringify(bans, null, 2));
}

function saveGiveaways() {
  fs.writeFileSync("./giveaways.json", JSON.stringify(activeGiveaways, null, 2));
}

/* =========================
   INVITES SYSTEM
========================= */
let invites = loadJSON("./invites.json", {});

function createInviteData() {
  return {
    total: 0,
    current: 0,
    left: 0,
    fake: 0,
    history: []
  };
}

function getInvite(userId) {
  if (!invites[userId]) {
    invites[userId] = createInviteData();
  }
  return invites[userId];
}

for (const userId in invites) {
  invites[userId] = {
    ...createInviteData(),
    ...invites[userId]
  };

  if (!Array.isArray(invites[userId].history)) {
    invites[userId].history = [];
  }

  invites[userId].total = invites[userId].total || 0;
  invites[userId].current = invites[userId].current || 0;
  invites[userId].left = invites[userId].left || 0;
  invites[userId].fake = invites[userId].fake || 0;
}

function saveInvites() {
  fs.writeFileSync("./invites.json", JSON.stringify(invites, null, 2));
}

/* ===================================================
   MESSAGES STATS & AFK SYSTEM STORAGE
=================================================== */
let messageStats = loadJSON("./messages.json", {});
let afkData = loadJSON("./afk.json", {});

function saveMessageStats() {
  fs.writeFileSync("./messages.json", JSON.stringify(messageStats, null, 2));
}

function saveAfkData() {
  fs.writeFileSync("./afk.json", JSON.stringify(afkData, null, 2));
}

function trackUserMessage(userId) {
  const now = new Date();
  if (!messageStats[userId]) {
    messageStats[userId] = {
      allTime: 0,
      today: 0,
      weekly: 0,
      monthly: 0,
      lastDaily: now.toDateString(),
      lastWeekly: getWeekNumber(now),
      lastMonthly: now.getMonth()
    };
  }

  const u = messageStats[userId];

  if (u.lastDaily !== now.toDateString()) {
    u.today = 0;
    u.lastDaily = now.toDateString();
  }

  if (u.lastWeekly !== getWeekNumber(now)) {
    u.weekly = 0;
    u.lastWeekly = getWeekNumber(now);
  }

  if (u.lastMonthly !== now.getMonth()) {
    u.monthly = 0;
    u.lastMonthly = now.getMonth();
  }

  u.allTime = (u.allTime || 0) + 1;
  u.today = (u.today || 0) + 1;
  u.weekly = (u.weekly || 0) + 1;
  u.monthly = (u.monthly || 0) + 1;

  saveMessageStats();
}

function getWeekNumber(d) {
  const date = new Date(Date.UTC(d.getFullYear(), d.getMonth(), d.getDate()));
  date.setUTCDate(date.getUTCDate() + 4 - (date.getUTCDay() || 7));
  const yearStart = new Date(Date.UTC(date.getUTCFullYear(), 0, 1));
  return Math.ceil((((date - yearStart) / 86400000) + 1) / 7);
}

function getResetTimers() {
  const now = new Date();

  const tomorrow = new Date(now);
  tomorrow.setHours(24, 0, 0, 0);
  const hoursLeftDaily = Math.max(0, Math.round((tomorrow - now) / 3600000));

  const endOfWeek = new Date(now);
  const day = now.getDay();
  const diff = (7 - day) % 7 || 7;
  endOfWeek.setDate(now.getDate() + diff);
  endOfWeek.setHours(0, 0, 0, 0);
  const daysLeftWeekly = Math.max(0, Math.ceil((endOfWeek - now) / 86400000));

  const nextMonth = new Date(now.getFullYear(), now.getMonth() + 1, 1);
  const daysLeftMonthly = Math.max(0, Math.ceil((nextMonth - now) / 86400000));

  return { daily: `${hoursLeftDaily}h`, weekly: `${daysLeftWeekly}d`, monthly: `${daysLeftMonthly}d` };
}

/* =========================
   DISCORD CLIENT
========================= */
const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.MessageContent,
    GatewayIntentBits.GuildMembers,
    GatewayIntentBits.GuildInvites,
    GatewayIntentBits.GuildVoiceStates,
    GatewayIntentBits.GuildModeration
  ],
  partials: [
    Partials.GuildMember,
    Partials.User,
    Partials.Message,
    Partials.Channel
  ]
});

const inviteCache = new Map();

/* =========================
   SLASH COMMAND DEFINITIONS (GLOBAL)
========================= */
const commands = [
  new SlashCommandBuilder()
    .setName("setpin")
    .setDescription("Set or change your server's Owner Security PIN (Server Owner Only)")
    .addStringOption(o =>
      o.setName("pin")
        .setDescription("New security PIN (min 4 characters)")
        .setRequired(true)
    )
    .addStringOption(o =>
      o.setName("old_pin")
        .setDescription("Current PIN (required if changing an existing PIN)")
        .setRequired(false)
    ),

  new SlashCommandBuilder()
    .setName("unlock")
    .setDescription("Unlock major owner actions for 10 minutes (Server Owner Only)")
    .addStringOption(o =>
      o.setName("pin")
        .setDescription("Your server's Owner Security PIN")
        .setRequired(true)
    ),

  new SlashCommandBuilder()
    .setName("lock")
    .setDescription("Immediately lock your Owner Security session (Server Owner Only)"),

  new SlashCommandBuilder()
    .setName("staff")
    .setDescription("Manage per-server staff roles and hierarchy (Server Owner Only)")
    .addSubcommand(sub =>
      sub.setName("add")
        .setDescription("Assign a staff role to a user in this server")
        .addUserOption(o => o.setName("user").setDescription("Target user").setRequired(true))
        .addStringOption(o =>
          o.setName("role")
            .setDescription("Staff role to assign")
            .setRequired(true)
            .addChoices(
              { name: "CEO / Chief", value: "ceo" },
              { name: "Senior Admin", value: "senior_admin" },
              { name: "Junior Admin", value: "junior_admin" },
              { name: "Manager", value: "manager" },
              { name: "Senior Moderator", value: "senior_moderator" },
              { name: "Junior Moderator", value: "junior_moderator" },
              { name: "Support Staff", value: "support_staff" }
            )
        )
    )
    .addSubcommand(sub =>
      sub.setName("remove")
        .setDescription("Remove a staff role from a user in this server")
        .addUserOption(o => o.setName("user").setDescription("Target user").setRequired(true))
        .addStringOption(o =>
          o.setName("role")
            .setDescription("Staff role to remove")
            .setRequired(true)
            .addChoices(
              { name: "CEO / Chief", value: "ceo" },
              { name: "Senior Admin", value: "senior_admin" },
              { name: "Junior Admin", value: "junior_admin" },
              { name: "Manager", value: "manager" },
              { name: "Senior Moderator", value: "senior_moderator" },
              { name: "Junior Moderator", value: "junior_moderator" },
              { name: "Support Staff", value: "support_staff" }
            )
        )
    )
    .addSubcommand(sub =>
      sub.setName("linkrole")
        .setDescription("Link a Discord @Role to a staff hierarchy tier")
        .addStringOption(o =>
          o.setName("tier")
            .setDescription("Staff hierarchy tier")
            .setRequired(true)
            .addChoices(
              { name: "CEO / Chief", value: "ceo" },
              { name: "Senior Admin", value: "senior_admin" },
              { name: "Junior Admin", value: "junior_admin" },
              { name: "Manager", value: "manager" },
              { name: "Senior Moderator", value: "senior_moderator" },
              { name: "Junior Moderator", value: "junior_moderator" },
              { name: "Support Staff", value: "support_staff" }
            )
        )
        .addRoleOption(o =>
          o.setName("role")
            .setDescription("Discord role to link (leave empty to unlink)")
            .setRequired(false)
        )
    )
    .addSubcommand(sub =>
      sub.setName("list")
        .setDescription("View all assigned staff roles in this server")
    ),

  new SlashCommandBuilder()
    .setName("elevate")
    .setDescription("Escalate the current ticket to the Server Owner or CEO")
    .addStringOption(o =>
      o.setName("target")
        .setDescription("Who to escalate this ticket to")
        .setRequired(true)
        .addChoices(
          { name: "Owner", value: "owner" },
          { name: "CEO / Chief", value: "ceo" }
        )
    )
    .addStringOption(o =>
      o.setName("reason")
        .setDescription("Reason (e.g., payment/cash matter or cannot assist further)")
        .setRequired(false)
    ),

  new SlashCommandBuilder()
    .setName("setchannel")
    .setDescription("Set a channel for a specific bot feature (Admin Only)")
    .addStringOption(o =>
      o.setName("feature")
        .setDescription("Choose which feature channel to configure")
        .setRequired(true)
        .addChoices(
          { name: "Welcome", value: "welcome" },
          { name: "Goodbye", value: "goodbye" },
          { name: "Boost", value: "boost" },
          { name: "Level Up", value: "level" },
          { name: "Invite Log", value: "invite" },
          { name: "Ticket Log", value: "ticket" },
          { name: "Join-to-Create VC", value: "jtc" },
          { name: "Audit Log", value: "audit" },
          { name: "Anti-Nuke Log", value: "antinuke" }
        )
    )
    .addChannelOption(o =>
      o.setName("channel")
        .setDescription("Target channel (leave empty to disable)")
        .setRequired(false)
    ),

  new SlashCommandBuilder()
    .setName("setmessage")
    .setDescription("Customize automated Welcome, Goodbye, or Boost messages (Admin Only)")
    .addStringOption(o =>
      o.setName("type")
        .setDescription("Which automated message to customize")
        .setRequired(true)
        .addChoices(
          { name: "Welcome Message", value: "welcome" },
          { name: "Goodbye Message", value: "goodbye" },
          { name: "Boost Message", value: "boost" }
        )
    )
    .addStringOption(o =>
      o.setName("message")
        .setDescription("Placeholders: {user}, {username}, {server}, {memberCount}")
        .setRequired(true)
    ),

  new SlashCommandBuilder()
    .setName("badword")
    .setDescription("Manage tiered AutoMod bad words in bad_words.json (Admin Only)")
    .addSubcommand(sub =>
      sub.setName("add")
        .setDescription("Add a word/phrase to warn, mute, or ban")
        .addStringOption(o =>
          o.setName("tier")
            .setDescription("Punishment tier")
            .setRequired(true)
            .addChoices(
              { name: "Warn", value: "warn" },
              { name: "Mute", value: "mute" },
              { name: "Ban", value: "ban" }
            )
        )
        .addStringOption(o =>
          o.setName("word")
            .setDescription("Word or phrase to block")
            .setRequired(true)
        )
    )
    .addSubcommand(sub =>
      sub.setName("remove")
        .setDescription("Remove a word/phrase from a tier")
        .addStringOption(o =>
          o.setName("tier")
            .setDescription("Punishment tier")
            .setRequired(true)
            .addChoices(
              { name: "Warn", value: "warn" },
              { name: "Mute", value: "mute" },
              { name: "Ban", value: "ban" }
            )
        )
        .addStringOption(o =>
          o.setName("word")
            .setDescription("Word or phrase to remove")
            .setRequired(true)
        )
    )
    .addSubcommand(sub =>
      sub.setName("list")
        .setDescription("View configured bad words by tier")
        .addStringOption(o =>
          o.setName("tier")
            .setDescription("Punishment tier (optional)")
            .setRequired(false)
            .addChoices(
              { name: "Warn", value: "warn" },
              { name: "Mute", value: "mute" },
              { name: "Ban", value: "ban" }
            )
        )
    ),

  new SlashCommandBuilder()
    .setName("leveladd")
    .setDescription("Add levels to a user (Admin Only)")
    .addUserOption(o => o.setName("user").setDescription("The target user").setRequired(true))
    .addIntegerOption(o => o.setName("amount").setDescription("Amount of levels to add").setRequired(true)),

  new SlashCommandBuilder()
    .setName("ban")
    .setDescription("Ban a user temporarily or permanently (Admin Only)")
    .addUserOption(o => o.setName("user").setDescription("The user to ban").setRequired(true))
    .addStringOption(o => o.setName("duration").setDescription("Ban duration (e.g. perm, 1h, 7d)").setRequired(true))
    .addStringOption(o => o.setName("reason").setDescription("Reason for ban").setRequired(false)),

  new SlashCommandBuilder()
    .setName("unban")
    .setDescription("Unban a user by their ID (Admin Only)")
    .addStringOption(o => o.setName("user_id").setDescription("The user's ID").setRequired(true)),

  new SlashCommandBuilder()
    .setName("warnlist")
    .setDescription("View warnings for a user")
    .addUserOption(o => o.setName("user").setDescription("The user to check").setRequired(true)),

  new SlashCommandBuilder()
    .setName("warn")
    .setDescription("Warn a user")
    .addUserOption(o => o.setName("user").setDescription("The user to warn").setRequired(true))
    .addStringOption(o => o.setName("reason").setDescription("Reason for warning").setRequired(false)),

  new SlashCommandBuilder()
    .setName("removewarn")
    .setDescription("Remove a specific warning from a user")
    .addUserOption(o => o.setName("user").setDescription("The target user").setRequired(true))
    .addIntegerOption(o => o.setName("number").setDescription("The warning number to remove").setRequired(true)),

  new SlashCommandBuilder()
    .setName("clearwarn")
    .setDescription("Clear all warnings for a user")
    .addUserOption(o => o.setName("user").setDescription("The target user").setRequired(true)),

  new SlashCommandBuilder()
    .setName("mutehistory")
    .setDescription("View mute history of a user")
    .addUserOption(o => o.setName("user").setDescription("The user to check").setRequired(true)),

  new SlashCommandBuilder()
    .setName("mute")
    .setDescription("Mute/timeout a user")
    .addUserOption(o => o.setName("user").setDescription("The user to mute").setRequired(true))
    .addStringOption(o => o.setName("reason").setDescription("Reason for mute").setRequired(false)),

  new SlashCommandBuilder()
    .setName("unmute")
    .setDescription("Unmute a user")
    .addUserOption(o => o.setName("user").setDescription("The user to unmute").setRequired(true)),

  new SlashCommandBuilder()
    .setName("banhistory")
    .setDescription("View ban history of a user")
    .addUserOption(o => o.setName("user").setDescription("The user to check").setRequired(true)),

  new SlashCommandBuilder()
    .setName("level")
    .setDescription("Check level and XP progress")
    .addUserOption(o => o.setName("user").setDescription("User to check (optional)").setRequired(false)),

  new SlashCommandBuilder()
    .setName("invitedashboard")
    .setDescription("View full invite statistics dashboard")
    .addUserOption(o => o.setName("user").setDescription("User to check (optional)").setRequired(false)),

  new SlashCommandBuilder()
    .setName("invite")
    .setDescription("Check invite statistics")
    .addUserOption(o => o.setName("user").setDescription("User to check (optional)").setRequired(false)),

  new SlashCommandBuilder()
    .setName("gstart")
    .setDescription("Start a giveaway")
    .addStringOption(o => o.setName("duration").setDescription("Duration (e.g. 10m, 2h, 1d)").setRequired(true))
    .addIntegerOption(o => o.setName("winners").setDescription("Number of winners").setRequired(true))
    .addStringOption(o => o.setName("prize").setDescription("Prize to give away").setRequired(true)),

  new SlashCommandBuilder()
    .setName("greroll")
    .setDescription("Reroll a giveaway winner")
    .addStringOption(o => o.setName("message_id").setDescription("Giveaway message ID").setRequired(true)),

  new SlashCommandBuilder()
    .setName("rules")
    .setDescription("View official server rules"),

  new SlashCommandBuilder()
    .setName("punishments")
    .setDescription("View server punishment guidelines"),

  new SlashCommandBuilder()
    .setName("tac")
    .setDescription("View community terms and conditions"),

  new SlashCommandBuilder()
    .setName("messages")
    .setDescription("View detailed message activity statistics")
    .addUserOption(o => o.setName("user").setDescription("Target user (optional)").setRequired(false)),

  new SlashCommandBuilder()
    .setName("afk")
    .setDescription("Set an AFK status with automated mention tracking")
    .addStringOption(o => o.setName("reason").setDescription("Reason for going AFK").setRequired(false)),

  new SlashCommandBuilder()
    .setName("howgay")
    .setDescription("Calculate gay percentage meter")
    .addUserOption(o => o.setName("user").setDescription("User to check (optional)").setRequired(false)),

  new SlashCommandBuilder()
    .setName("panel")
    .setDescription("Send the support ticket creation panel"),

  new SlashCommandBuilder()
    .setName("tictactoe")
    .setDescription("Play Tic Tac Toe")
    .addStringOption(o =>
      o.setName("mode")
        .setDescription("Choose game mode")
        .setRequired(true)
        .addChoices(
          { name: "Singleplayer (vs Hard Bot)", value: "s" },
          { name: "Multiplayer (vs Friend)", value: "m" }
        )
    )
    .addUserOption(o => o.setName("opponent").setDescription("Mention player (Multiplayer only)").setRequired(false)),

  new SlashCommandBuilder()
    .setName("wordle")
    .setDescription("Play a game of Wordle"),

  new SlashCommandBuilder()
    .setName("guess")
    .setDescription("Play Guess the Number (1 - 10000)"),

  new SlashCommandBuilder()
    .setName("snake")
    .setDescription("Play retro Snake arcade game"),

  new SlashCommandBuilder()
    .setName("help")
    .setDescription("View all available commands, categories, and syntax instructions")
    .addStringOption(o =>
      o.setName("category")
        .setDescription("Filter commands by category")
        .setRequired(false)
        .addChoices(
          { name: "🌐 General & Server Info", value: "info" },
          { name: "⚙️ Server Setup & AutoMod", value: "setup" },
          { name: "📊 Levels & Invites", value: "stats" },
          { name: "🎮 Mini-Games & Fun", value: "games" },
          { name: "🛡️ Staff & Moderation", value: "mod" }
        )
    ),

  new SlashCommandBuilder()
    .setName("leaderboard")
    .setDescription("View server rankings for Levels, Daily Chat, and Invites")
    .addStringOption(o =>
      o.setName("type")
        .setDescription("Choose leaderboard type")
        .setRequired(false)
        .addChoices(
          { name: "⭐ Levels & XP", value: "levels" },
          { name: "💬 Daily Chat", value: "daily" }
        )
    )
];

/* =========================
   READY EVENT
========================= */
client.once("ready", async () => {
  console.log(`${client.user.tag} is online across ${client.guilds.cache.size} server(s)!`);

  // Register Global Slash Commands for All Servers
  const rest = new REST({ version: "10" }).setToken(client.token || process.env.DISCORD_TOKEN);
  try {
    console.log("Registering global application (/) commands...");
    await rest.put(
      Routes.applicationCommands(client.user.id),
      { body: commands.map(c => c.toJSON()) }
    );
    console.log("Global application (/) commands successfully registered!");
  } catch (err) {
    console.error("Failed to register global slash commands:", err);
  }

  // Cache invites across all servers
  client.guilds.cache.forEach(async (guild) => {
    getGuildConfig(guild.id);
    const guildInvites = await guild.invites.fetch().catch(() => {});
    if (!guildInvites) return;

    const cache = new Map();
    guildInvites.forEach((inv) => {
      cache.set(inv.code, inv.uses);
    });

    inviteCache.set(guild.id, cache);
  });

  /* =========================
     BACKGROUND GIVEAWAY CHECKER
  ========================= */
  setInterval(async () => {
    const now = Date.now();

    for (let gw of activeGiveaways) {
      if (!gw.ended && now >= gw.endsAt) {
        gw.ended = true;
        saveGiveaways();

        try {
          const channel = await client.channels.fetch(gw.channelId).catch(() => null);
          if (!channel) continue;

          const msg = await channel.messages.fetch(gw.messageId).catch(() => null);
          if (!msg) continue;

          let winners = [];
          const pool = [...gw.entries];

          while (winners.length < gw.winnerCount && pool.length > 0) {
            const randIdx = Math.floor(Math.random() * pool.length);
            winners.push(pool.splice(randIdx, 1)[0]);
          }

          const winnersFormatted = winners.length > 0
            ? winners.map((id) => `├── <@${id}>`).join("\n")
            : "├── *No valid entries*";

          const endedEmbed = new EmbedBuilder()
            .setColor(0x2B2D31)
            .setTitle("🏆 GIVEAWAY ENDED 🏆")
            .setDescription(
              `🏆 **Prize:** ${gw.prize}\n\n` +
              `🎉 **Winners:**\n${winnersFormatted}\n\n` +
              `👑 **Hosted by:** <@${gw.hostId}>`
            )
            .setFooter({ text: `Total Entries: ${gw.entries.length}` })
            .setTimestamp();

          const endedButton = new ButtonBuilder()
            .setCustomId("giveaway_ended")
            .setLabel("Giveaway Ended")
            .setEmoji("✅")
            .setStyle(ButtonStyle.Secondary)
            .setDisabled(true);

          const endedRow = new ActionRowBuilder().addComponents(endedButton);

          await msg.edit({ embeds: [endedEmbed], components: [endedRow] }).catch(() => {});

          if (winners.length > 0) {
            channel.send(`🎉 Congratulations ${winners.map((id) => `<@${id}>`).join(", ")}! You won **${gw.prize}**!`).catch(() => {});
          } else {
            channel.send("❌ Giveaway ended with no entries.").catch(() => {});
          }
        } catch (err) {
          console.error("Error ending giveaway:", err);
        }
      }
    }
  }, 10000);
});

// Cache invites & init config when added to a new server
client.on("guildCreate", async (guild) => {
  getGuildConfig(guild.id);
  const guildInvites = await guild.invites.fetch().catch(() => {});
  if (!guildInvites) return;

  const cache = new Map();
  guildInvites.forEach((inv) => cache.set(inv.code, inv.uses));
  inviteCache.set(guild.id, cache);
});

/* =========================
   PASSIVE XP, CLAIM LOCK & TIERED AUTOMOD
========================= */
client.on("messageCreate", async (message) => {
  if (!message.guild || message.author.bot) return;

  const member = message.member || await message.guild.members.fetch(message.author.id).catch(() => null);
  const bypass = isStaff(member);
  const cfg = getGuildConfig(message.guild.id);

  /* --- TICKET CLAIM LOCK: ONLY CLAIMANT OR SERVER OWNER CAN INTERVENE --- */
  if (isTicketChannel(message.channel)) {
    const info = parseTicketTopic(message.channel.topic);
    const ownerCheck = isServerOwner(message.author, message.guild);

    if (info.claimedById && message.author.id !== info.claimedById && message.author.id !== info.openerId && !ownerCheck) {
      if (member && canManageTickets(member)) {
        await message.delete().catch(() => {});
        const warnNotice = await message.channel.send({
          content: `🔒 ${message.author}, this ticket is claimed by <@${info.claimedById}>. Only the claiming staff member or the **Server Owner** can intervene here.`
        }).catch(() => {});
        if (warnNotice) setTimeout(() => warnNotice.delete().catch(() => {}), 5000);
        return;
      }
    }
  }

  /* --- 1. TRACK MESSAGE STATS --- */
  trackUserMessage(message.author.id);

  /* --- 2. AFK SYSTEM: CLEAR AFK UPON TALKING --- */
  if (afkData[message.author.id]?.isAfk) {
    const data = afkData[message.author.id];
    delete afkData[message.author.id];
    saveAfkData();

    const welcomeMsg = await message.reply(`👋 Welcome back ${message.author}, I have removed your AFK status.`).catch(() => {});
    setTimeout(() => welcomeMsg?.delete().catch(() => {}), 6000);

    if (data.mentions && data.mentions.length > 0) {
      const mentionList = data.mentions.slice(0, 10).map((m, i) => {
        return `**${i + 1}.** **${m.author}** mentioned you:\n> ${m.content}\n[Jump to Message](${m.url})`;
      }).join("\n\n");

      const mentionEmbed = new EmbedBuilder()
        .setColor(0x2B2D31)
        .setTitle(`Mention History for ${message.author.username}`)
        .setDescription(mentionList)
        .setFooter({ text: `Total Mentions: ${data.mentions.length} | Today` })
        .setTimestamp();

      await message.author.send({ embeds: [mentionEmbed] }).catch(() => {});
    }
  }

  /* --- 3. AFK SYSTEM: DETECT PINGS TO AFK USERS --- */
  if (message.mentions.users.size > 0) {
    message.mentions.users.forEach(async (target) => {
      if (target.id !== message.author.id && afkData[target.id]?.isAfk) {
        const afkEntry = afkData[target.id];

        message.reply(`💤 **${target.displayName || target.username}** is currently AFK: ${afkEntry.reason}`).catch(() => {});

        if (!afkEntry.mentions) afkEntry.mentions = [];
        afkEntry.mentions.push({
          author: message.author.tag,
          content: message.cleanContent.slice(0, 300),
          url: message.url,
          timestamp: Date.now()
        });
        saveAfkData();
      }
    });
  }

  /* --- 4. AUTOMOD FILTERS (TIER 1, 2, 3 & INVITES) --- */
  if (!bypass) {
    if (DISCORD_INVITE_REGEX.test(message.content)) {
      await message.delete().catch(() => {});
      issueAutoWarning(message.author.id, "Unauthorized server invite or promotion link");
      return;
    }

    const banTerm = findMatchedTerm(message.content, badWordsDB.ban);
    if (banTerm) {
      await message.delete().catch(() => {});
      await message.guild.members.ban(message.author.id, { reason: `[AutoMod Tier 3] Prohibited: "${banTerm}"` }).catch(() => {});
      return;
    }

    const muteTerm = findMatchedTerm(message.content, badWordsDB.mute);
    if (muteTerm) {
      await message.delete().catch(() => {});
      await member?.timeout(2 * 3600000, `[AutoMod Tier 2] Prohibited: "${muteTerm}"`).catch(() => {});
      return;
    }

    const warnTerm = findMatchedTerm(message.content, badWordsDB.warn);
    if (warnTerm) {
      await message.delete().catch(() => {});
      issueAutoWarning(message.author.id, `Prohibited word: "${warnTerm}"`);
      return;
    }
  }

  /* --- 5. PASSIVE CHAT XP & AESTHETIC LEVEL-UP CARD --- */
  const userId = message.author.id;
  if (!levels[userId]) {
    levels[userId] = { xp: 0, level: 1 };
  }

  levels[userId].xp += 10;
  const neededXP = levels[userId].level * 100;

  if (levels[userId].xp >= neededXP) {
    levels[userId].xp -= neededXP;
    levels[userId].level++;
    saveLevels();

    const levelChannel = (cfg.channels.level && client.channels.cache.get(cfg.channels.level)) || message.channel;
    if (levelChannel) {
      const levelUpEmbed = new EmbedBuilder()
        .setColor(0x00A8FC)
        .setTitle("🎉 LEVEL UP!")
        .setDescription(
          "🌸 **A NEW DECREE** 🌸\n\n" +
          "**CONGRATULATIONS** 🧑‍🌾\n" +
          `**${message.member?.displayName || message.author.username}!** YOU REACHED **LEVEL ${levels[userId].level}** 💧\n\n` +
          "🕊️ **KEEP STRIVING 〜**\n" +
          "**GREATNESS AWAITS**\n" +
          "**AT THE NEXT STEP OF 〜**\n" +
          "**YOUR PATH 〜 <3.** 🕊️"
        )
        .setThumbnail(message.author.displayAvatarURL({ dynamic: true, size: 256 }));

      await levelChannel.send({
        content: `${message.author}`,
        embeds: [levelUpEmbed]
      }).catch(() => {});
    }
  } else {
    saveLevels();
  }
});

/* =========================
   SLASH COMMANDS & INTERACTIONS
========================= */
client.on("interactionCreate", async (interaction) => {

  /* =========================
     CHAT INPUT COMMANDS
  ========================= */
  if (interaction.isChatInputCommand()) {
    const { commandName } = interaction;
    const member = interaction.member;

    function noPerm() {
      return interaction.reply({
        content: "❌ You don't have permission to do this.",
        ephemeral: true
      });
    }

    /* --- SET OR CHANGE SERVER OWNER PIN --- */
    if (commandName === "setpin") {
      if (!isServerOwner(interaction.user, interaction.guild)) {
        return interaction.reply({ content: "❌ Only the **Server Owner** can set or change this server's PIN.", flags: MessageFlags.Ephemeral });
      }

      const newPin = interaction.options.getString("pin").trim();
      const oldPin = interaction.options.getString("old_pin");

      if (newPin.length < 4) {
        return interaction.reply({ content: "❌ Your PIN must be at least **4 characters** long.", flags: MessageFlags.Ephemeral });
      }

      if (hasGuildOwnerPin(interaction.guildId)) {
        if (!oldPin || !verifyGuildOwnerPin(interaction.guildId, oldPin)) {
          return interaction.reply({ content: "❌ A PIN is already set for this server. Provide the correct `old_pin` to change it.", flags: MessageFlags.Ephemeral });
        }
      }

      setGuildOwnerPin(interaction.guildId, newPin);
      unlockedOwnerSessions.set(`${interaction.guildId}:${interaction.user.id}`, Date.now() + OWNER_SESSION_DURATION_MS);

      return interaction.reply({
        content: "✅ **Personal Owner PIN Saved!** Your session is unlocked for **10 minutes**. Keep this PIN private—changing it in the future requires your current PIN.",
        flags: MessageFlags.Ephemeral
      });
    }

    /* --- UNLOCK OWNER SECURITY SESSION --- */
    if (commandName === "unlock") {
      if (!isServerOwner(interaction.user, interaction.guild)) {
        return interaction.reply({ content: "❌ Only the **Server Owner** can use this command.", flags: MessageFlags.Ephemeral });
      }

      if (!hasGuildOwnerPin(interaction.guildId)) {
        return interaction.reply({ content: "⚠️ No PIN is set yet. Run `/setpin pin:<your_pin>` first.", flags: MessageFlags.Ephemeral });
      }

      const pinInput = interaction.options.getString("pin");
      if (!verifyGuildOwnerPin(interaction.guildId, pinInput)) {
        console.warn(`[SECURITY ALERT] Failed Owner PIN attempt in ${interaction.guild.name} (${interaction.guild.id}) by ${interaction.user.tag}.`);
        return interaction.reply({ content: "❌ Invalid Owner PIN.", flags: MessageFlags.Ephemeral });
      }

      unlockedOwnerSessions.set(`${interaction.guildId}:${interaction.user.id}`, Date.now() + OWNER_SESSION_DURATION_MS);
      return interaction.reply({
        content: "✅ **Owner Session Unlocked** for **10 minutes**.",
        flags: MessageFlags.Ephemeral
      });
    }

    /* --- LOCK OWNER SECURITY SESSION --- */
    if (commandName === "lock") {
      if (!isServerOwner(interaction.user, interaction.guild)) {
        return interaction.reply({ content: "❌ Only the **Server Owner** can use this command.", flags: MessageFlags.Ephemeral });
      }

      unlockedOwnerSessions.delete(`${interaction.guildId}:${interaction.user.id}`);
      return interaction.reply({
        content: "🔒 **Owner Session Locked.** Major actions now require `/unlock`.",
        flags: MessageFlags.Ephemeral
      });
    }

    /* --- STAFF ROLE MANAGEMENT (SERVER OWNER ONLY) --- */
    if (commandName === "staff") {
      if (!isServerOwner(interaction.user, interaction.guild)) {
        return interaction.reply({
          content: "❌ Only the **Server Owner** can assign or configure staff roles.",
          ephemeral: true
        });
      }

      const sub = interaction.options.getSubcommand();
      if (sub !== "list" && !(await requireOwnerAuth(interaction))) return;

      const cfg = getGuildConfig(interaction.guildId);
      const staffCfg = ensureStaffConfig(cfg);

      if (sub === "add") {
        const targetUser = interaction.options.getUser("user");
        const roleKey = interaction.options.getString("role");
        const meta = STAFF_ROLES_META[roleKey];

        if (!Array.isArray(staffCfg.users[targetUser.id])) {
          staffCfg.users[targetUser.id] = [];
        }
        if (!staffCfg.users[targetUser.id].includes(roleKey)) {
          staffCfg.users[targetUser.id].push(roleKey);
        }
        saveServerConfigs();

        return interaction.reply({
          content: `✅ Assigned **${meta.label}** to ${targetUser} in **${interaction.guild.name}**.`,
          ephemeral: true
        });
      }

      if (sub === "remove") {
        const targetUser = interaction.options.getUser("user");
        const roleKey = interaction.options.getString("role");
        const meta = STAFF_ROLES_META[roleKey];

        if (Array.isArray(staffCfg.users[targetUser.id])) {
          staffCfg.users[targetUser.id] = staffCfg.users[targetUser.id].filter(r => r !== roleKey);
          if (staffCfg.users[targetUser.id].length === 0) {
            delete staffCfg.users[targetUser.id];
          }
          saveServerConfigs();
        }

        return interaction.reply({
          content: `🗑️ Removed **${meta.label}** from ${targetUser} in **${interaction.guild.name}**.`,
          ephemeral: true
        });
      }

      if (sub === "linkrole") {
        const tier = interaction.options.getString("tier");
        const discordRole = interaction.options.getRole("role");
        const meta = STAFF_ROLES_META[tier];

        staffCfg.roleLinks[tier] = discordRole ? discordRole.id : null;
        saveServerConfigs();

        return interaction.reply({
          content: discordRole
            ? `🔗 Linked Discord role ${discordRole} to **${meta.label}**.`
            : `🔓 Unlinked Discord role for **${meta.label}**.`,
          ephemeral: true
        });
      }

      if (sub === "list") {
        const entries = Object.entries(staffCfg.users);
        const userLines = entries.length
          ? entries.map(([uid, rKeys]) => {
              const labels = rKeys.map(k => STAFF_ROLES_META[k]?.label || k).join(", ");
              return `• <@${uid}> — **${labels}**`;
            }).join("\n")
          : "*No individual staff assignments set yet.*";

        const linkLines = Object.entries(STAFF_ROLES_META).map(([k, meta]) => {
          const rid = staffCfg.roleLinks[k];
          return `• **${meta.label}:** ${rid ? `<@&${rid}>` : "*Not linked*"}`;
        }).join("\n");

        const embed = new EmbedBuilder()
          .setColor(0x8600FF)
          .setTitle(`🛡️ ${interaction.guild.name} • Staff Hierarchy`)
          .addFields(
            { name: "Assigned Staff Members", value: userLines, inline: false },
            { name: "Linked Discord Roles", value: linkLines, inline: false }
          )
          .setTimestamp();

        return interaction.reply({ embeds: [embed], ephemeral: true });
      }
    }

    /* --- ELEVATE TICKET TO OWNER OR CEO --- */
    if (commandName === "elevate") {
      if (!isTicketChannel(interaction.channel)) {
        return interaction.reply({
          content: "❌ This command can only be used inside a ticket channel.",
          flags: MessageFlags.Ephemeral
        });
      }

      const info = parseTicketTopic(interaction.channel.topic);
      const ownerCheck = isServerOwner(interaction.user, interaction.guild);
      const isClaimer = info.claimedById === interaction.user.id;

      if (!ownerCheck && !isClaimer) {
        return interaction.reply({
          content: info.claimedById
            ? `❌ Only the staff member who claimed this ticket (<@${info.claimedById}>) or the **Server Owner** can elevate it.`
            : "❌ Claim this ticket first before elevating it.",
          flags: MessageFlags.Ephemeral
        });
      }

      const target = interaction.options.getString("target");
      const reason = interaction.options.getString("reason") || "Payment / cash matter or further assistance required";

      const ceoInfo = getServerCeoTargets(interaction.guild);
      const mentions = [];

      if (target === "owner") {
        mentions.push(`<@${interaction.guild.ownerId}>`);
      } else if (target === "ceo") {
        for (const uid of ceoInfo.userIds) mentions.push(`<@${uid}>`);
        for (const rid of ceoInfo.roleIds) mentions.push(`<@&${rid}>`);
        if (mentions.length === 0) mentions.push(`<@${interaction.guild.ownerId}>`);
      }

      if (target === "ceo") {
        for (const uid of ceoInfo.userIds) {
          await interaction.channel.permissionOverwrites.edit(uid, {
            ViewChannel: true,
            SendMessages: true,
            ReadMessageHistory: true,
            AttachFiles: true
          }).catch(() => {});
        }
        for (const rid of ceoInfo.roleIds) {
          await interaction.channel.permissionOverwrites.edit(rid, {
            ViewChannel: true,
            SendMessages: true,
            ReadMessageHistory: true,
            AttachFiles: true
          }).catch(() => {});
        }
      }

      const newStatus = target === "owner" ? "Escalated to Owner" : "Escalated to CEO";
      await interaction.channel.setTopic(
        buildTicketTopic({
          openerId: info.openerId,
          claimedById: info.claimedById,
          status: newStatus
        })
      ).catch(() => {});

      const elevateEmbed = new EmbedBuilder()
        .setColor(0xF59E0B)
        .setTitle(`📣 Ticket Elevated to ${target === "owner" ? "Server Owner" : "CEO / Chief"}`)
        .setDescription(
          `**Elevated By:** ${interaction.user}\n` +
          `**Escalated To:** ${mentions.join(", ")}\n` +
          `**Reason:** ${reason}`
        )
        .setTimestamp();

      await interaction.channel.send({
        content: `🔔 Attention ${mentions.join(" ")} — this ticket has been escalated!`,
        embeds: [elevateEmbed]
      });

      return interaction.reply({
        content: `✅ Ticket elevated to **${target === "owner" ? "Owner" : "CEO"}**.`,
        flags: MessageFlags.Ephemeral
      });
    }

    /* --- SETCHANNEL (ADMIN ONLY) --- */
    if (commandName === "setchannel") {
      if (!isGuildAdmin(member)) return noPerm();
      if (!(await requireOwnerAuth(interaction))) return;

      const feature = interaction.options.getString("feature");
      const channel = interaction.options.getChannel("channel");
      const cfg = getGuildConfig(interaction.guildId);

      cfg.channels[feature] = channel ? channel.id : null;
      saveServerConfigs();

      return interaction.reply({
        content: channel
          ? `✅ **${feature.toUpperCase()}** channel set to ${channel}.`
          : `🗑️ Cleared **${feature.toUpperCase()}** channel setting.`,
        ephemeral: true
      });
    }

    /* --- SETMESSAGE (ADMIN ONLY) --- */
    if (commandName === "setmessage") {
      if (!isGuildAdmin(member)) return noPerm();
      if (!(await requireOwnerAuth(interaction))) return;

      const type = interaction.options.getString("type");
      const text = interaction.options.getString("message").trim();
      const cfg = getGuildConfig(interaction.guildId);

      cfg.messages[type] = text;
      saveServerConfigs();

      const preview = formatTemplate(text, { member: interaction.member, guild: interaction.guild, level: 5 });
      return interaction.reply({
        content: `✅ Updated **${type}** message template!\n\n**Preview:**\n${preview}`,
        ephemeral: true
      });
    }

    /* --- BADWORD MANAGER (ADMIN ONLY) --- */
    if (commandName === "badword") {
      if (!isGuildAdmin(member)) return noPerm();

      const sub = interaction.options.getSubcommand();
      if (sub !== "list" && !(await requireOwnerAuth(interaction))) return;

      if (sub === "add") {
        const tier = interaction.options.getString("tier");
        const word = interaction.options.getString("word").trim().toLowerCase();
        if (!word) return interaction.reply({ content: "❌ Provide a valid word or phrase.", ephemeral: true });

        if (!Array.isArray(badWordsDB[tier])) badWordsDB[tier] = [];
        if (badWordsDB[tier].some(w => w.toLowerCase() === word)) {
          return interaction.reply({ content: `⚠️ \`${word}\` is already in **${tier.toUpperCase()}**.`, ephemeral: true });
        }

        badWordsDB[tier].push(word);
        fs.writeFileSync("./bad_words.json", JSON.stringify(badWordsDB, null, 2));
        return interaction.reply({
          content: `✅ Added \`${word}\` to **${tier.toUpperCase()}** AutoMod list.`,
          ephemeral: true
        });
      }

      if (sub === "remove") {
        const tier = interaction.options.getString("tier");
        const word = interaction.options.getString("word").trim().toLowerCase();
        if (!Array.isArray(badWordsDB[tier])) badWordsDB[tier] = [];

        const before = badWordsDB[tier].length;
        badWordsDB[tier] = badWordsDB[tier].filter(w => w.toLowerCase() !== word);
        if (badWordsDB[tier].length === before) {
          return interaction.reply({ content: `❌ \`${word}\` was not found in **${tier.toUpperCase()}**.`, ephemeral: true });
        }

        fs.writeFileSync("./bad_words.json", JSON.stringify(badWordsDB, null, 2));
        return interaction.reply({
          content: `🗑️ Removed \`${word}\` from **${tier.toUpperCase()}** AutoMod list.`,
          ephemeral: true
        });
      }

      if (sub === "list") {
        const tierFilter = interaction.options.getString("tier");
        const tiersToShow = tierFilter ? [tierFilter] : ["warn", "mute", "ban"];

        const lines = tiersToShow.map(t => {
          const list = badWordsDB[t] || [];
          return `**${t.toUpperCase()} (${list.length}):** ${list.length ? list.map(w => `\`${w}\``).join(", ") : "*None*"}`;
        });

        const embed = new EmbedBuilder()
          .setColor(0x8600FF)
          .setTitle("🛡️ AutoMod Bad Words List")
          .setDescription(lines.join("\n\n"))
          .setTimestamp();

        return interaction.reply({ embeds: [embed], ephemeral: true });
      }
    }

    /* --- LEVELADD (ADMIN ONLY) --- */
    if (commandName === "leveladd") {
      if (!isGuildAdmin(member)) return noPerm();
      if (!(await requireOwnerAuth(interaction))) return;

      const target = interaction.options.getUser("user");
      const amount = interaction.options.getInteger("amount");
      const userId = target.id;

      if (!levels[userId]) {
        levels[userId] = { xp: 0, level: 1 };
      }

      levels[userId].level += amount;
      saveLevels();

      return interaction.reply(
        `✅ ${target.tag} has been given **${amount} levels**! Now level **${levels[userId].level}**`
      );
    }

    /* --- BAN (ADMIN ONLY) --- */
    if (commandName === "ban") {
      if (!canBan(member)) return noPerm();
      if (!(await requireOwnerAuth(interaction))) return;

      const targetUser = interaction.options.getUser("user");
      const duration = interaction.options.getString("duration");
      const reason = interaction.options.getString("reason") || "No reason provided";
      const targetMember = await interaction.guild.members.fetch(targetUser.id).catch(() => null);

      if (targetMember && !canActOnTarget(member, targetMember)) {
        return interaction.reply({ content: "❌ You cannot ban someone of equal or higher staff rank.", ephemeral: true });
      }

      if (!bans[targetUser.id]) {
        bans[targetUser.id] = { history: [] };
      }

      if (duration.toLowerCase() === "perm" || duration.toLowerCase() === "permanent") {
        bans[targetUser.id].history.push({
          action: "Permanent Ban",
          moderator: interaction.user.tag,
          reason,
          duration: "Permanent",
          date: Date.now()
        });

        saveBans();
        await interaction.guild.members.ban(targetUser.id, { reason });

        return interaction.reply(
          `🔨 ${targetUser.tag} permanently banned.\nReason: ${reason}`
        );
      }

      const durationMs = ms(duration);
      if (!durationMs) return interaction.reply({ content: "❌ Use: 1h, 1d, 7d, 30d, etc.", ephemeral: true });

      bans[targetUser.id].history.push({
        action: "Temp Ban",
        moderator: interaction.user.tag,
        reason,
        duration,
        expires: Date.now() + durationMs,
        date: Date.now()
      });

      saveBans();
      await interaction.guild.members.ban(targetUser.id, { reason: `${reason} | Temp Ban` });

      interaction.reply(
        `🔨 ${targetUser.tag} banned for ${duration}`
      );

      setTimeout(async () => {
        try {
          await interaction.guild.members.unban(targetUser.id);
          if (!bans[targetUser.id]) return;

          bans[targetUser.id].history.push({
            action: "Auto Unban (Expired)",
            moderator: "System",
            date: Date.now()
          });

          saveBans();
          interaction.channel?.send(
            `🔓 ${targetUser.tag}'s temporary ban expired.`
          ).catch(() => {});
        } catch {}
      }, durationMs);
      return;
    }

    /* --- UNBAN (ADMIN ONLY) --- */
    if (commandName === "unban") {
      if (!canBan(member)) return noPerm();
      if (!(await requireOwnerAuth(interaction))) return;

      const userId = interaction.options.getString("user_id");

      try {
        await interaction.guild.members.unban(userId);

        if (!bans[userId]) {
          bans[userId] = { history: [] };
        }

        bans[userId].history.push({
          action: "Manual Unban",
          moderator: interaction.user.tag,
          date: Date.now()
        });

        saveBans();
        return interaction.reply(`🔓 User ${userId} has been unbanned.`);
      } catch {
        return interaction.reply({ content: "❌ Failed to unban user. Make sure the ID is valid.", ephemeral: true });
      }
    }

    /* --- WARNLIST --- */
    if (commandName === "warnlist") {
      if (!canWarn(member)) return noPerm();

      const target = interaction.options.getUser("user");
      const warns = warnings[target.id] || [];

      if (warns.length === 0) {
        return interaction.reply(`✅ ${target.tag} has no warnings.`);
      }

      const list = warns
        .map((w, i) => {
          const date = new Date(w.date).toLocaleDateString();
          return `**${i + 1}.** ${w.reason}\n📅 ${date}`;
        })
        .join("\n\n");

      const embed = new EmbedBuilder()
        .setColor(0x8600FF)
        .setTitle("⚠️ Warning History")
        .setDescription(`👤 ${target.tag}\n\n${list}`)
        .setFooter({ text: `Total: ${warns.length}` })
        .setTimestamp();

      return interaction.reply({ embeds: [embed] });
    }

    /* --- WARN --- */
    if (commandName === "warn") {
      if (!canWarn(member)) return noPerm();

      const target = interaction.options.getUser("user");
      const reason = interaction.options.getString("reason") || "No reason provided";
      const targetMember = await interaction.guild.members.fetch(target.id).catch(() => null);

      if (targetMember && !canActOnTarget(member, targetMember)) {
        return interaction.reply({ content: "❌ You cannot warn someone of equal or higher staff rank.", ephemeral: true });
      }

      if (!warnings[target.id]) warnings[target.id] = [];

      warnings[target.id].push({
        reason,
        date: Date.now()
      });

      saveWarnings();
      return interaction.reply(
        `⚠️ ${target.tag} warned.\nReason: ${reason}`
      );
    }

    /* --- REMOVEWARN --- */
    if (commandName === "removewarn") {
      if (!canWarn(member)) return noPerm();

      const target = interaction.options.getUser("user");
      const num = interaction.options.getInteger("number");
      const warns = warnings[target.id] || [];

      if (num < 1 || num > warns.length) {
        return interaction.reply({ content: "❌ Invalid warning number.", ephemeral: true });
      }

      warns.splice(num - 1, 1);
      warnings[target.id] = warns;
      saveWarnings();

      return interaction.reply(
        `✅ Removed warning #${num} from ${target.tag}`
      );
    }

    /* --- CLEARWARN --- */
    if (commandName === "clearwarn") {
      if (!canWarn(member)) return noPerm();

      const target = interaction.options.getUser("user");
      warnings[target.id] = [];
      saveWarnings();

      return interaction.reply(
        `✅ Cleared all warnings for ${target.tag}`
      );
    }

    /* --- MUTEHISTORY --- */
    if (commandName === "mutehistory") {
      if (!canMute(member)) return noPerm();

      const target = interaction.options.getUser("user");
      const data = mutes[target.id];

      if (!data || !data.history.length) {
        return interaction.reply(`✅ ${target.tag} has no mute history.`);
      }

      const text = data.history
        .map((m, i) => {
          const date = new Date(m.date).toLocaleDateString();
          return `**${i + 1}. ${m.action}**\n👮 ${m.moderator}\n📌 ${m.reason || "N/A"}\n📅 ${date}`;
        })
        .join("\n\n");

      const embed = new EmbedBuilder()
        .setColor(0xFEE75C)
        .setTitle("🔇 Mute History")
        .setDescription(`👤 ${target.tag}\n\n${text}`)
        .setTimestamp();

      return interaction.reply({ embeds: [embed] });
    }

    /* --- MUTE --- */
    if (commandName === "mute") {
      if (!canMute(member)) return noPerm();

      const targetUser = interaction.options.getUser("user");
      const reason = interaction.options.getString("reason") || "No reason provided";
      const targetMember = await interaction.guild.members.fetch(targetUser.id).catch(() => null);

      if (!targetMember) return interaction.reply({ content: "❌ Target member not found.", ephemeral: true });

      if (!canActOnTarget(member, targetMember)) {
        return interaction.reply({ content: "❌ You cannot mute someone of equal or higher staff rank.", ephemeral: true });
      }

      await targetMember.timeout(28 * 24 * 60 * 60 * 1000, reason).catch(() => null);

      if (!mutes[targetUser.id]) {
        mutes[targetUser.id] = { history: [] };
      }

      mutes[targetUser.id].history.push({
        action: "Mute",
        moderator: interaction.user.tag,
        reason,
        date: Date.now()
      });

      saveMutes();
      return interaction.reply(
        `🔇 ${targetUser.tag} has been muted.\nReason: ${reason}`
      );
    }

    /* --- UNMUTE --- */
    if (commandName === "unmute") {
      if (!canMute(member)) return noPerm();

      const targetUser = interaction.options.getUser("user");
      const targetMember = await interaction.guild.members.fetch(targetUser.id).catch(() => null);

      if (!targetMember) return interaction.reply({ content: "❌ Target member not found.", ephemeral: true });

      await targetMember.timeout(null).catch(() => null);

      if (!mutes[targetUser.id]) {
        mutes[targetUser.id] = { history: [] };
      }

      mutes[targetUser.id].history.push({
        action: "Unmute",
        moderator: interaction.user.tag,
        date: Date.now()
      });

      saveMutes();
      return interaction.reply(`🔊 ${targetUser.tag} has been unmuted.`);
    }

    /* --- BANHISTORY --- */
    if (commandName === "banhistory") {
      if (!canBan(member)) return noPerm();

      const target = interaction.options.getUser("user");
      const data = bans[target.id];

      if (!data || !data.history.length) {
        return interaction.reply(`✅ ${target.tag} has no ban history.`);
      }

      const text = data.history
        .map((b, i) => {
          const date = new Date(b.date).toLocaleDateString();
          return `**${i + 1}. ${b.action}**\n👮 ${b.moderator}\n📌 ${b.reason || "N/A"}\n⏳ ${b.duration || "N/A"}\n📅 ${date}`;
        })
        .join("\n\n");

      const embed = new EmbedBuilder()
        .setColor(0xED4245)
        .setTitle("⚖️ Ban History")
        .setDescription(`👤 ${target.tag}\n\n${text}`)
        .setTimestamp();

      return interaction.reply({ embeds: [embed] });
    }

    /* --- HELP MENU COMMAND --- */
    if (commandName === "help") {
      const selectedCategory = interaction.options.getString("category") || "overview";

      function getHelpEmbed(cat) {
        if (cat === "info") {
          return new EmbedBuilder()
            .setColor(0x8600FF)
            .setTitle("🌐 Server & General Commands")
            .setDescription(
              "• **`/rules`**\n" +
              "  └ View the official Discord server rules and conduct policy.\n\n" +
              "• **`/punishments`**\n" +
              "  └ View punishment ladders and enforcement guidelines.\n\n" +
              "• **`/tac`**\n" +
              "  └ Read community terms and conditions.\n\n" +
              "• **`/panel`**\n" +
              "  └ Deploy the interactive support ticket dropdown panel.\n\n" +
              "• **`/elevate [target] [reason]`**\n" +
              "  └ Escalate a claimed ticket to the Server Owner or CEO.\n\n" +
              "• **`/help [category]`**\n" +
              "  └ Open this interactive command directory."
            )
            .setImage(BANNER)
            .setFooter({ text: "Category: General & Information" })
            .setTimestamp();
        }

        if (cat === "setup") {
          return new EmbedBuilder()
            .setColor(0x8600FF)
            .setTitle("⚙️ Server Setup & AutoMod Commands")
            .setDescription(
              "• **`/setpin [pin] [old_pin]`**\n" +
              "  └ *(Server Owner)* Set or change your personal 2FA PIN for major actions.\n\n" +
              "• **`/unlock [pin]`** & **`/lock`**\n" +
              "  └ *(Server Owner)* Unlock a 10-minute major-action session or lock immediately.\n\n" +
              "• **`/staff add | remove | linkrole | list`**\n" +
              "  └ *(Server Owner)* Assign CEO, Senior Admin, Junior Admin, Manager, Senior Mod, Junior Mod, or Support Staff.\n\n" +
              "• **`/setchannel [feature] [channel]`**\n" +
              "  └ Set channels for Welcome, Goodbye, Boost, Level Up, Invite Log, Ticket Log, Join-to-Create VC, Audit Log, or Anti-Nuke Log.\n\n" +
              "• **`/setmessage [type] [message]`**\n" +
              "  └ Customize Welcome, Goodbye, or Boost text using `{user}`, `{username}`, `{server}`, `{memberCount}`.\n\n" +
              "• **`/badword add | remove | list`**\n" +
              "  └ Manage AutoMod words in `warn`, `mute`, or `ban` tiers."
            )
            .setImage(BANNER)
            .setFooter({ text: "Category: Server Setup & AutoMod" })
            .setTimestamp();
        }

        if (cat === "stats") {
          return new EmbedBuilder()
            .setColor(0x8600FF)
            .setTitle("📊 Levels, Invites & Ranking")
            .setDescription(
              "• **`/level [user]`**\n" +
              "  └ Check current chat level, XP progress, and visual status bar.\n\n" +
              "• **`/leaderboard [type]`**\n" +
              "  └ View top 10 rankings for **Levels** or **Daily Chat**.\n\n" +
              "• **`/messages [user]`**\n" +
              "  └ View all-time, monthly, weekly, and daily chat message counts.\n\n" +
              "• **`/afk [reason]`**\n" +
              "  └ Set an AFK status with automated mention tracking.\n\n" +
              "• **`/invite [user]`**\n" +
              "  └ View quick overview of your real, fake, and left invites.\n\n" +
              "• **`/invitedashboard [user]`**\n" +
              "  └ Display complete invite analytics, efficiency ratings, and tracked joins."
            )
            .setImage(BANNER)
            .setFooter({ text: "Category: Levels & Invites" })
            .setTimestamp();
        }

        if (cat === "games") {
          return new EmbedBuilder()
            .setColor(0x8600FF)
            .setTitle("🎮 Mini-Games & Arcade")
            .setDescription(
              "• **`/snake`**\n" +
              "  └ Play the retro button-controlled Snake arcade game in Discord.\n\n" +
              "• **`/tictactoe [mode] [opponent]`**\n" +
              "  └ Play Tic Tac Toe against an unbeatable AI or challenge a friend.\n\n" +
              "• **`/wordle`**\n" +
              "  └ Guess the secret 5-letter word within 6 tries.\n\n" +
              "• **`/guess`**\n" +
              "  └ Guess the hidden number between 1 and 10,000.\n\n" +
              "• **`/howgay [user]`**\n" +
              "  └ Fun meter calculating random rainbow affinity score."
            )
            .setImage(BANNER)
            .setFooter({ text: "Category: Mini-Games & Fun" })
            .setTimestamp();
        }

        if (cat === "mod") {
          return new EmbedBuilder()
            .setColor(0xED4245)
            .setTitle("🛡️ Staff & Moderation Commands")
            .setDescription(
              "• **`/warn [user] [reason]`** — Issue a server warning.\n" +
              "• **`/warnlist [user]`** — Inspect all active warnings on a user.\n" +
              "• **`/removewarn [user] [number]`** — Delete a specific warning index.\n" +
              "• **`/clearwarn [user]`** — Clear all warning records for a user.\n" +
              "• **`/mute [user] [reason]`** — Timeout a member for 28 days.\n" +
              "• **`/unmute [user]`** — Remove active timeout from a member.\n" +
              "• **`/mutehistory [user]`** — Inspect full past timeout logs.\n" +
              "• **`/banhistory [user]`** — Inspect past temporary/permanent ban logs.\n" +
              "• **`/gstart [duration] [winners] [prize]`** — Host persistent giveaway.\n" +
              "• **`/greroll [message_id]`** — Reroll giveaway winner from stored entries.\n" +
              "• **`/ban [user] [duration] [reason]`** — *(Admin)* Temp/perm ban.\n" +
              "• **`/unban [user_id]`** — *(Admin)* Revoke a server ban by user ID.\n" +
              "• **`/leveladd [user] [amount]`** — *(Admin)* Award bonus chat levels."
            )
            .setImage(BANNER)
            .setFooter({ text: "Category: Staff Moderation (Restricted)" })
            .setTimestamp();
        }

        return new EmbedBuilder()
          .setColor(0x8600FF)
          .setAuthor({ name: "Bot Command Directory", iconURL: THUMBNAIL })
          .setTitle("📖 Command Directory")
          .setDescription(
            "Welcome to the official command manual.\n" +
            "Select a module from the dropdown menu below to inspect commands, parameters, and usage.\n\n" +
            "**Directory Modules:**\n" +
            "• **🌐 General & Server** — Rules, guidelines, tickets, and terms\n" +
            "• **⚙️ Server Setup & AutoMod** — Owner PIN, staff roles, channels, messages, and bad words\n" +
            "• **📊 Levels & Invites** — Level progress, invite tracking, AFK, and leaderboards\n" +
            "• **🎮 Mini-Games** — Snake, TicTacToe, Wordle, and Guess games\n" +
            "• **🛡️ Staff Operations** — Full moderation suite and giveaway system"
          )
          .setImage(BANNER)
          .setFooter({ text: "Use the dropdown below to browse" })
          .setTimestamp();
      }

      const menu = new StringSelectMenuBuilder()
        .setCustomId("help_menu")
        .setPlaceholder("Select a command module to inspect")
        .addOptions([
          { label: "Overview", description: "Main directory page", emoji: "📖", value: "overview" },
          { label: "General & Server Info", description: "Server rules, tickets, and guidelines", emoji: "🌐", value: "info" },
          { label: "Server Setup & AutoMod", description: "Owner PIN, staff roles, channels, messages, and bad words", emoji: "⚙️", value: "setup" },
          { label: "Levels & Invites", description: "Level cards, invite stats, and leaderboards", emoji: "📊", value: "stats" },
          { label: "Mini-Games & Fun", description: "Snake, TicTacToe, Wordle, and Guess", emoji: "🎮", value: "games" },
          { label: "Staff & Moderation", description: "Warns, mutes, bans, and giveaways", emoji: "🛡️", value: "mod" }
        ]);

      const selectRow = new ActionRowBuilder().addComponents(menu);

      const helpMessage = await interaction.reply({
        embeds: [getHelpEmbed(selectedCategory)],
        components: [selectRow],
        fetchReply: true
      });

      const collector = helpMessage.createMessageComponentCollector({
        filter: (i) => i.user.id === interaction.user.id,
        time: 5 * 60 * 1000
      });

      collector.on("collect", async (i) => {
        if (i.isStringSelectMenu() && i.customId === "help_menu") {
          const selected = i.values[0];
          await i.update({
            embeds: [getHelpEmbed(selected)],
            components: [selectRow]
          }).catch(() => {});
        }
      });

      collector.on("end", async () => {
        const disabledRow = new ActionRowBuilder().addComponents(
          menu.setDisabled(true)
        );
        await helpMessage.edit({ components: [disabledRow] }).catch(() => {});
      });

      return;
    }

    /* --- LEVEL --- */
    if (commandName === "level") {
      const targetUser = interaction.options.getUser("user") || interaction.user;
      const userId = targetUser.id;

      if (!levels[userId]) {
        levels[userId] = { xp: 0, level: 1 };
      }

      const userXP = levels[userId].xp;
      const userLevel = levels[userId].level;
      const neededXP = userLevel * 100;

      const percent = Math.min(10, Math.max(0, Math.floor((userXP / neededXP) * 10)));
      const filledBar = "█".repeat(percent);
      const emptyBar = "░".repeat(10 - percent);
      const progressBar = `${filledBar}${emptyBar}`;

      const embed = new EmbedBuilder()
        .setColor(0x8600FF)
        .setTitle("📊 Level Info")
        .setDescription(
          `👤 User: **${targetUser.tag}**\n` +
          `⭐ Level: **${userLevel}**\n` +
          `⚡ XP: **${userXP}/${neededXP}**\n\n` +
          `📈 Progress:\n${progressBar}`
        );

      return interaction.reply({ embeds: [embed] });
    }

    /* --- INVITE DASHBOARD --- */
    if (commandName === "invitedashboard") {
      const targetUser = interaction.options.getUser("user") || interaction.user;
      const data = getInvite(targetUser.id);
      const totalHistory = data.history.length;

      const embed = new EmbedBuilder()
        .setColor(0x8600FF)
        .setTitle("📊 Invite Dashboard")
        .setThumbnail(targetUser.displayAvatarURL({ dynamic: true }))
        .setDescription(
          `👤 **User:** ${targetUser.tag}\n\n` +
          `✅ **Total Invites:** ${data.total}\n` +
          `✨ **Current Invites:** ${data.current}\n` +
          `⚠️ **Left Invites:** ${data.left}\n` +
          `❌ **Fake Invites:** ${data.fake}\n\n` +
          `📜 **Total Joins Tracked:** ${totalHistory}`
        )
        .addFields(
          {
            name: "📘 Breakdown",
            value:
              `✨ Real Invites: ${data.current}\n` +
              `⚠️ Fake Invites: ${data.fake}\n` +
              `❌ Left Users: ${data.left}`
          },
          {
            name: "📈 Efficiency",
            value:
              data.total > 0
                ? `${Math.floor((data.current / data.total) * 100)}% Real Invites`
                : "0% Real Invites"
          }
        )
        .setTimestamp();

      return interaction.reply({ embeds: [embed] });
    }

    /* --- INVITE CHECK --- */
    if (commandName === "invite") {
      const targetUser = interaction.options.getUser("user") || interaction.user;
      const data = getInvite(targetUser.id);

      const embed = new EmbedBuilder()
        .setColor(0x8600FF)
        .setTitle("📨 Invite Overview")
        .setThumbnail(targetUser.displayAvatarURL({ dynamic: true }))
        .setDescription(
          `👤 **User:** ${targetUser.tag}\n\n` +
          `✅ **Total Invites:** ${data.total}\n` +
          `✨ **Current Invites:** ${data.current}\n` +
          `❌ **Left Invites:** ${data.left}\n` +
          `⚠️ **Fake Invites:** ${data.fake}`
        )
        .setFooter({ text: "Use /invitedashboard for full stats view" })
        .setTimestamp();

      return interaction.reply({ embeds: [embed] });
    }

    /* --- PERSISTENT GIVEAWAY START --- */
    if (commandName === "gstart") {
      if (!isStaff(member)) return noPerm();

      const timeInput = interaction.options.getString("duration");
      const winnerCount = interaction.options.getInteger("winners");
      const prize = interaction.options.getString("prize");

      const durationMs = ms(timeInput);
      if (!durationMs || durationMs < 5000) {
        return interaction.reply({ content: "❌ Invalid duration! Use formats like `1m`, `30m`, `2h`, `1d`.", ephemeral: true });
      }

      const endTimestamp = Math.floor((Date.now() + durationMs) / 1000);
      const endsAt = Date.now() + durationMs;

      const giveawayEmbed = new EmbedBuilder()
        .setColor(0x8600FF)
        .setTitle(`🎉 ${interaction.guild.name.toUpperCase()} • GIVEAWAY 🎉`)
        .setDescription(
          `🎁 **Prize:** ${prize}\n` +
          `✨ **Hosted by:** ${interaction.user}\n` +
          `👑 **Winners:** **${winnerCount}**\n` +
          `⏳ **Ends:** <t:${endTimestamp}:R> (<t:${endTimestamp}:f>)\n\n` +
          `Click the **🎉 Enter** button below to participate!`
        )
        .setImage(BANNER)
        .setFooter({ text: `Entries: 0 | Ends at` })
        .setTimestamp(endsAt);

      const enterButton = new ButtonBuilder()
        .setCustomId("giveaway_enter")
        .setLabel("Enter (0)")
        .setEmoji("🎉")
        .setStyle(ButtonStyle.Success);

      const row = new ActionRowBuilder().addComponents(enterButton);

      const giveawayMsg = await interaction.reply({
        embeds: [giveawayEmbed],
        components: [row],
        fetchReply: true
      });

      activeGiveaways.push({
        messageId: giveawayMsg.id,
        channelId: interaction.channelId,
        guildId: interaction.guildId,
        hostId: interaction.user.id,
        prize,
        winnerCount,
        endsAt,
        ended: false,
        entries: []
      });
      saveGiveaways();
      return;
    }

    /* --- PERSISTENT GIVEAWAY REROLL --- */
    if (commandName === "greroll") {
      if (!isStaff(member)) return noPerm();

      const targetId = interaction.options.getString("message_id");
      const gw = activeGiveaways.find((g) => g.messageId === targetId);

      if (!gw) {
        return interaction.reply({ content: "❌ Could not find an active or saved giveaway with that message ID!", ephemeral: true });
      }

      if (!gw.ended) {
        return interaction.reply({ content: "❌ That giveaway is still active and hasn't ended yet!", ephemeral: true });
      }

      if (!gw.entries || gw.entries.length === 0) {
        return interaction.reply({ content: "❌ Cannot reroll: There were no valid entries in that giveaway.", ephemeral: true });
      }

      const newWinner = gw.entries[Math.floor(Math.random() * gw.entries.length)];

      return interaction.reply({
        content: `🎉 **New Winner Rerolled!** Congratulations <@${newWinner}>! You won **${gw.prize}**!`
      });
    }

    /* --- RULES --- */
    if (commandName === "rules") {
      const embed = new EmbedBuilder()
        .setColor(0x8600FF)
        .setTitle(`📘 ${interaction.guild.name} — Official Server Rules`)
        .setDescription(`
# 📘 ${interaction.guild.name} — Official Server Rules

━━━━━━━━━━━━━━

## 💬 **1. Chat Rules**
➤ Keep the chat clean, friendly, and respectful. Toxicity, harassment, hate speech, discrimination, excessive swearing, spam, or inappropriate behavior is strictly prohibited.

━━━━━━━━━━━━━━

## 📢 **2. Proper Channel Usage**
➤ Use channels correctly and avoid unnecessary spam, advertising, or disruptive behavior. Keep conversations meaningful and respectful.

━━━━━━━━━━━━━━

## ⚠️ **3. Follow Discord Guidelines**
➤ All members must follow the official Discord Community Guidelines and Terms of Service at all times.

━━━━━━━━━━━━━━

## 🔊 **4. Voice Chat Rules**
➤ Keep VC conversations friendly and appropriate. Mic spam, earrape, excessive background noise, harassment, or disturbing others is not allowed.

━━━━━━━━━━━━━━

## ⚖️ **5. Punishment System**
➤ Warning → Mute → Kick → Temporary Ban → Permanent Ban

━━━━━━━━━━━━━━

## 💡 **6. Use Common Sense**
➤ Not every situation can be covered by rules. Use common sense and respect staff decisions to help maintain a positive and fair community.
`)
        .setThumbnail(interaction.guild.iconURL() || THUMBNAIL)
        .setImage(BANNER)
        .setFooter({ text: `${interaction.guild.name} Rules` })
        .setTimestamp();

      return interaction.reply({ embeds: [embed] });
    }

    /* --- PUNISHMENTS --- */
    if (commandName === "punishments") {
      const embed = new EmbedBuilder()
        .setColor(0x8600FF)
        .setTitle(`⚖️ ${interaction.guild.name} • Punishment System`)
        .setDescription(`
━━━━━━━━━━━━━━━━━━━━━━━━
# **📢 Punishment System**
━━━━━━━━━━━━━━━━━━━━━━━━

➤ Most violations will result in a Warning first.

➤ Repeated violations may result in Mutes, Temporary Bans, or Permanent Bans.

━━━━━━━━━━━━━━

➤ Chat Spam & Advertising
Warning → Mute → Temporary Ban

➤ Harassment, Toxicity & Hate Speech
Warning → Mute → Temporary Ban → Permanent Ban

➤ Staff Impersonation
Warning → Temporary Ban → Permanent Ban

➤ Ban Evasion
Permanent Ban

━━━━━━━━━━━━━━━━━━━━━━━━
# **⚠️ Final Notice**
━━━━━━━━━━━━━━━━━━━━━━━━

➤ Staff may issue harsher punishments immediately for severe offenses.

➤ Use common sense and respect staff decisions. Staff decisions are final.
`)
        .setImage(BANNER)
        .setFooter({ text: `${interaction.guild.name} Guidelines` })
        .setTimestamp();

      return interaction.reply({ embeds: [embed] });
    }

    /* --- TAC --- */
    if (commandName === "tac") {
      const embed = new EmbedBuilder()
        .setColor(0x8600FF)
        .setTitle(`📋 ${interaction.guild.name} • Terms & Conditions`)
        .setDescription(`
━━━━━━━━━━━━━━━━━━━━━━
**📢 Community Policy**
━━━━━━━━━━━━━━━━━━━━━━

➤ By participating in **${interaction.guild.name}**, you agree to follow all server rules and Discord's official Terms of Service.

➤ Members are responsible for the security of their own Discord accounts.

➤ Moderation actions are enforced based on evidence and severity at staff discretion.
`)
        .setImage(BANNER)
        .setFooter({ text: `${interaction.guild.name} Terms` })
        .setTimestamp();

      return interaction.reply({ embeds: [embed] });
    }

    /* --- HOWGAY --- */
    if (commandName === "howgay") {
      const user = interaction.options.getUser("user") || interaction.user;
      const gayPercent = Math.floor(Math.random() * 101);

      const filled = "▰".repeat(Math.floor(gayPercent / 10));
      const empty = "▱".repeat(10 - Math.floor(gayPercent / 10));

      const embed = new EmbedBuilder()
        .setColor(0xFF69B4)
        .setTitle("🏳️‍🌈 Gay-O-Meter")
        .setDescription(
          `**Target:** ${user}\n\n` +
          `**Gay Level:** ${gayPercent}%\n` +
          `${filled}${empty}\n\n` +
          `*This is just for fun! Results are completely random.*`
        )
        .setThumbnail(user.displayAvatarURL({ dynamic: true }))
        .setFooter({ text: `Requested by ${interaction.user.username}` })
        .setTimestamp();

      return interaction.reply({ embeds: [embed] });
    }

    /* --- TICKET PANEL --- */
    if (commandName === "panel") {
      const embed = new EmbedBuilder()
        .setColor(0x8600FF)
        .setTitle(`🎟️ ${interaction.guild.name} Ticket System`)
        .setDescription(
          "Select a ticket type from the dropdown menu below.\n\n" +
          "❓ General Support\n" +
          "⚠️ Member Reports\n" +
          "⚖️ Punishment Appeals"
        )
        .setImage(BANNER)
        .setThumbnail(interaction.guild.iconURL() || THUMBNAIL)
        .setFooter({ text: `${interaction.guild.name} Support Center` });

      const menu = new StringSelectMenuBuilder()
        .setCustomId("ticket_menu")
        .setPlaceholder("Select a ticket type")
        .addOptions([
          {
            label: "General Support",
            description: "Need help from staff",
            emoji: "❓",
            value: "support"
          },
          {
            label: "Member Report",
            description: "Report a rule violator",
            emoji: "⚠️",
            value: "report"
          },
          {
            label: "Punishment Appeal",
            description: "Appeal your punishment",
            emoji: "⚖️",
            value: "appeal"
          }
        ]);

      const row = new ActionRowBuilder().addComponents(menu);

      return interaction.reply({ embeds: [embed], components: [row] });
    }

    /* --- TIC TAC TOE --- */
    if (commandName === "tictactoe") {
      const type = interaction.options.getString("mode");
      let player1 = interaction.user;
      let player2 = null;
      let isBotGame = type === "s";

      if (isBotGame) {
        player2 = { id: "bot", username: `${client.user.username}`, tag: `${client.user.username}` };
      } else {
        player2 = interaction.options.getUser("opponent");
        if (!player2 || player2.bot || player2.id === player1.id) {
          return interaction.reply({ content: "❌ Please mention a valid player to challenge!", ephemeral: true });
        }
      }

      let board = Array(9).fill(null);
      let turn = player1.id;

      function makeRows() {
        const rows = [];
        for (let i = 0; i < 3; i++) {
          const row = new ActionRowBuilder();
          for (let j = 0; j < 3; j++) {
            const index = i * 3 + j;
            const style = board[index] === "❌" ? ButtonStyle.Danger : board[index] === "⭕" ? ButtonStyle.Success : ButtonStyle.Secondary;
            row.addComponents(
              new ButtonBuilder()
                .setCustomId(`ttt_${index}`)
                .setLabel(board[index] || "➖")
                .setStyle(style)
                .setDisabled(board[index] !== null)
            );
          }
          rows.push(row);
        }
        return rows;
      }

      function checkWin() {
        const lines = [
          [0, 1, 2], [3, 4, 5], [6, 7, 8],
          [0, 3, 6], [1, 4, 7], [2, 5, 8],
          [0, 4, 8], [2, 4, 6]
        ];
        for (const line of lines) {
          if (board[line[0]] && board[line[0]] === board[line[1]] && board[line[0]] === board[line[2]]) {
            return board[line[0]];
          }
        }
        return board.includes(null) ? null : "tie";
      }

      function evaluateBoard(b) {
        const lines = [
          [0, 1, 2], [3, 4, 5], [6, 7, 8],
          [0, 3, 6], [1, 4, 7], [2, 5, 8],
          [0, 4, 8], [2, 4, 6]
        ];
        for (const line of lines) {
          if (b[line[0]] && b[line[0]] === b[line[1]] && b[line[0]] === b[line[2]]) {
            return b[line[0]] === "⭕" ? 10 : -10;
          }
        }
        return 0;
      }

      function minimax(tempBoard, depth, isMax) {
        let score = evaluateBoard(tempBoard);
        if (score === 10) return score - depth;
        if (score === -10) return score + depth;
        if (!tempBoard.includes(null)) return 0;

        if (isMax) {
          let best = -1000;
          for (let i = 0; i < 9; i++) {
            if (tempBoard[i] === null) {
              tempBoard[i] = "⭕";
              best = Math.max(best, minimax(tempBoard, depth + 1, false));
              tempBoard[i] = null;
            }
          }
          return best;
        } else {
          let best = 1000;
          for (let i = 0; i < 9; i++) {
            if (tempBoard[i] === null) {
              tempBoard[i] = "❌";
              best = Math.min(best, minimax(tempBoard, depth + 1, true));
              tempBoard[i] = null;
            }
          }
          return best;
        }
      }

      function findBestMove() {
        let bestVal = -1000;
        let bestMove = -1;
        for (let i = 0; i < 9; i++) {
          if (board[i] === null) {
            board[i] = "⭕";
            let moveVal = minimax(board, 0, false);
            board[i] = null;
            if (moveVal > bestVal) {
              bestMove = i;
              bestVal = moveVal;
            }
          }
        }
        return bestMove;
      }

      const gameMessage = await interaction.reply({
        content: `❌ **${player1} (X)** vs ⭕ **${isBotGame ? player2.username : player2} (O)**\n\n🎯 Current Turn: <@${turn}>\n⏳ *You have 15 minutes to make a move!*`,
        components: makeRows(),
        fetchReply: true
      });

      const collector = gameMessage.createMessageComponentCollector({
        filter: (i) => i.user.id === player1.id || i.user.id === (isBotGame ? "" : player2.id),
        time: 15 * 60 * 1000
      });

      collector.on("collect", async (i) => {
        if (i.user.id !== turn) {
          return i.reply({ content: "❌ It is not your turn!", ephemeral: true });
        }

        const index = parseInt(i.customId.split("_")[1]);
        board[index] = turn === player1.id ? "❌" : "⭕";

        let status = checkWin();

        if (status) {
          collector.stop(status);
          await i.deferUpdate().catch(() => {});
          return;
        }

        turn = turn === player1.id ? player2.id : player1.id;

        if (isBotGame && turn === "bot") {
          const botMove = findBestMove();
          if (botMove !== -1) {
            board[botMove] = "⭕";
            status = checkWin();
            if (status) {
              collector.stop(status);
              await i.deferUpdate().catch(() => {});
              return;
            }
            turn = player1.id;
          }
        }

        collector.resetTimer({ time: 15 * 60 * 1000 });

        await i.update({
          content: `❌ **${player1.username}** vs ⭕ **${isBotGame ? player2.username : player2.username}**\n\n🎯 Current Turn: <@${turn}>\n⏳ *15 minutes remaining for this turn!*`,
          components: makeRows()
        }).catch(() => {});
      });

      collector.on("end", async (collected, reason) => {
        const disabledRows = makeRows().map(row => {
          row.components.forEach(btn => btn.setDisabled(true));
          return row;
        });

        if (reason === "❌") {
          await gameMessage.edit({ content: `🎉 **Game Over!** ${player1} (X) won the match!`, components: disabledRows }).catch(() => {});
        } else if (reason === "⭕") {
          await gameMessage.edit({ content: `🎉 **Game Over!** ${isBotGame ? player2.username : player2} (O) won the match!`, components: disabledRows }).catch(() => {});
        } else if (reason === "tie") {
          await gameMessage.edit({ content: `🤝 **Game Over!** It's a tie match!`, components: disabledRows }).catch(() => {});
        } else {
          await gameMessage.edit({ content: `⚠️ **Game Over!** Game timed out because a player took longer than 15 minutes to move.`, components: disabledRows }).catch(() => {});
        }
      });
      return;
    }

    /* --- WORDLE --- */
    if (commandName === "wordle") {
      const words = ["apple", "beach", "craft", "drive", "elder", "flame", "grape", "house", "image", "juice", "knife", "lemon", "melon", "night", "ocean", "paper", "queen", "river", "stone", "tiger", "unity", "vocal", "whale", "youth", "zebra"];
      const targetWord = words[Math.floor(Math.random() * words.length)];
      let attempts = 0;
      let maxAttempts = 6;
      let gameBoard = [];

      const startEmbed = new EmbedBuilder()
        .setColor(0x8600FF)
        .setTitle("📝 Wordle Game Initialized!")
        .setDescription(`I've picked a secret **5-letter word**. You have **6 tries** to guess it right!\n\n⏳ You have **15 minutes** to submit each guess. Type your 5-letter words below!`)
        .setFooter({ text: `Requested by ${interaction.user.username}` })
        .setTimestamp();

      await interaction.reply({ embeds: [startEmbed] });

      const collector = interaction.channel.createMessageCollector({
        filter: (m) => m.author.id === interaction.user.id,
        time: 15 * 60 * 1000
      });

      collector.on("collect", async (m) => {
        const guess = m.content.toLowerCase().trim();

        if (guess.length !== 5) {
          return m.reply("⚠️ Your guess must be exactly **5 letters** long!").then(msg => setTimeout(() => msg.delete().catch(() => {}), 3000));
        }

        attempts++;
        let remainingLetters = targetWord;

        let trackingMatches = Array(5).fill("⬛");
        for (let i = 0; i < 5; i++) {
          if (guess[i] === targetWord[i]) {
            trackingMatches[i] = "🟩";
            remainingLetters = remainingLetters.replace(guess[i], "");
          }
        }

        for (let i = 0; i < 5; i++) {
          if (trackingMatches[i] !== "🟩" && remainingLetters.includes(guess[i])) {
            trackingMatches[i] = "🟨";
            remainingLetters = remainingLetters.replace(guess[i], "");
          }
        }

        gameBoard.push(trackingMatches.join("") + `  |  **${guess.toUpperCase()}**`);
        collector.resetTimer({ time: 15 * 60 * 1000 });

        const statusEmbed = new EmbedBuilder()
          .setColor(0x8600FF)
          .setTitle("📝 Wordle Tracker")
          .setDescription(gameBoard.join("\n") + "\n\n⏳ *Timer reset! 15 minutes left for your next guess.*")
          .setFooter({ text: `Attempt ${attempts}/${maxAttempts}` })
          .setTimestamp();

        await m.reply({ embeds: [statusEmbed] }).catch(() => {});

        if (guess === targetWord) {
          collector.stop("win");
        } else if (attempts >= maxAttempts) {
          collector.stop("lose");
        }
      });

      collector.on("end", async (collected, reason) => {
        if (reason === "win") {
          interaction.channel.send(`🎉 Congratulations ${interaction.user}! You guessed the correct word **${targetWord.toUpperCase()}** in ${attempts} tries!`);
        } else if (reason === "lose") {
          interaction.channel.send(`❌ Game Over ${interaction.user}! You've run out of tries. The secret word was **${targetWord.toUpperCase()}**.`);
        } else {
          interaction.channel.send(`⚠️ ${interaction.user}, your Wordle session timed out because you took longer than 15 minutes to guess.`);
        }
      });
      return;
    }

    /* --- GUESS THE NUMBER --- */
    if (commandName === "guess") {
      const targetNumber = Math.floor(Math.random() * 10000) + 1;
      let attempts = 0;

      const startEmbed = new EmbedBuilder()
        .setColor(0x8600FF)
        .setTitle("🔢 Guess the Number!")
        .setDescription("I have chosen a secret number between **1 and 10000**.\n\nType your guesses directly into this channel. You have **15 minutes** to submit each guess!")
        .setFooter({ text: `Player: ${interaction.user.username}` })
        .setTimestamp();

      await interaction.reply({ embeds: [startEmbed] });

      const collector = interaction.channel.createMessageCollector({
        filter: (m) => m.author.id === interaction.user.id,
        time: 15 * 60 * 1000
      });

      collector.on("collect", async (m) => {
        const guess = parseInt(m.content.trim());
        if (isNaN(guess)) return;

        attempts++;
        collector.resetTimer({ time: 15 * 60 * 1000 });

        if (guess === targetNumber) {
          collector.stop("win");
        } else if (guess > targetNumber) {
          await m.reply(`🔻 **${guess}** is **too high**! Try a lower number. *(Attempt: ${attempts})*`).catch(() => {});
        } else {
          await m.reply(`🔺 **${guess}** is **too low**! Try a higher number. *(Attempt: ${attempts})*`).catch(() => {});
        }
      });

      collector.on("end", async (collected, reason) => {
        if (reason === "win") {
          interaction.channel.send(`🎉 **Congratulations ${interaction.user}!** You guessed the correct number **${targetNumber}** in **${attempts}** attempts!`);
        } else {
          interaction.channel.send(`⚠️ ${interaction.user}, your Guess the Number session timed out because you took longer than 15 minutes. The secret number was **${targetNumber}**.`);
        }
      });
      return;
    }

    /* --- SNAKE --- */
    if (commandName === "snake") {
      const width = 5;
      const height = 5;
      let score = 0;

      let snake = [{ x: 2, y: 2 }];
      let apple = { x: 0, y: 0 };

      function generateApple() {
        while (true) {
          const randX = Math.floor(Math.random() * width);
          const randY = Math.floor(Math.random() * height);
          if (!snake.some(segment => segment.x === randX && segment.y === randY)) {
            apple = { x: randX, y: randY };
            break;
          }
        }
      }
      generateApple();

      function drawBoard() {
        let boardString = "";
        for (let y = 0; y < height; y++) {
          for (let x = 0; x < width; x++) {
            if (snake[0].x === x && snake[0].y === y) {
              boardString += "🟩";
            } else if (snake.some(segment => segment.x === x && segment.y === y)) {
              boardString += "🟢";
            } else if (apple.x === x && apple.y === y) {
              boardString += "🍎";
            } else {
              boardString += "⬛";
            }
          }
          boardString += "\n";
        }
        return boardString;
      }

      const gameEmbed = new EmbedBuilder()
        .setColor(0x8600FF)
        .setTitle("🐍 Retro Snake Game")
        .setDescription(drawBoard())
        .addFields({ name: "🏆 Score", value: `**${score}**`, inline: true })
        .setFooter({ text: "Click the buttons below to control your snake!" })
        .setTimestamp();

      const controlRow = new ActionRowBuilder().addComponents(
        new ButtonBuilder().setCustomId("snake_up").setEmoji("⬆️").setStyle(ButtonStyle.Primary),
        new ButtonBuilder().setCustomId("snake_down").setEmoji("⬇️").setStyle(ButtonStyle.Primary),
        new ButtonBuilder().setCustomId("snake_left").setEmoji("⬅️").setStyle(ButtonStyle.Primary),
        new ButtonBuilder().setCustomId("snake_right").setEmoji("➡️").setStyle(ButtonStyle.Primary),
        new ButtonBuilder().setCustomId("snake_stop").setEmoji("🛑").setStyle(ButtonStyle.Danger)
      );

      const gameMessage = await interaction.reply({
        embeds: [gameEmbed],
        components: [controlRow],
        fetchReply: true
      });

      const collector = gameMessage.createMessageComponentCollector({
        filter: (i) => i.user.id === interaction.user.id,
        time: 15 * 60 * 1000
      });

      collector.on("collect", async (i) => {
        let moveX = 0;
        let moveY = 0;

        if (i.customId === "snake_stop") {
          collector.stop("stopped");
          await i.deferUpdate().catch(() => {});
          return;
        }

        if (i.customId === "snake_up") moveY = -1;
        if (i.customId === "snake_down") moveY = 1;
        if (i.customId === "snake_left") moveX = -1;
        if (i.customId === "snake_right") moveX = 1;

        const newHead = { x: snake[0].x + moveX, y: snake[0].y + moveY };

        if (newHead.x < 0 || newHead.x >= width || newHead.y < 0 || newHead.y >= height) {
          collector.stop("dead");
          await i.deferUpdate().catch(() => {});
          return;
        }

        if (snake.some(segment => segment.x === newHead.x && segment.y === newHead.y)) {
          collector.stop("dead");
          await i.deferUpdate().catch(() => {});
          return;
        }

        snake.unshift(newHead);

        if (newHead.x === apple.x && newHead.y === apple.y) {
          score += 10;
          if (snake.length >= width * height) {
            collector.stop("win");
            await i.deferUpdate().catch(() => {});
            return;
          }
          generateApple();
        } else {
          snake.pop();
        }

        collector.resetTimer({ time: 15 * 60 * 1000 });

        const updatedEmbed = EmbedBuilder.from(gameEmbed)
          .setDescription(drawBoard())
          .setFields({ name: "🏆 Score", value: `**${score}**`, inline: true });

        await i.update({
          embeds: [updatedEmbed],
          components: [controlRow]
        }).catch(() => {});
      });

      collector.on("end", async (collected, reason) => {
        const disabledRow = new ActionRowBuilder().addComponents(
          controlRow.components.map(button => ButtonBuilder.from(button).setDisabled(true))
        );

        const finalEmbed = new EmbedBuilder()
          .setColor(reason === "win" ? 0x57F287 : 0xED4245)
          .setTitle(reason === "win" ? "👑 Flawless Victory!" : "💀 Game Over!")
          .addFields({ name: "📘 Final Score", value: `**${score}** points`, inline: true })
          .setTimestamp();

        if (reason === "dead") {
          finalEmbed.setDescription(`You crashed into a wall or bit your own tail!\n\n**Final Grid:**\n${drawBoard()}`);
        } else if (reason === "stopped") {
          finalEmbed.setDescription(`The game was manually ended by the user.\n\n**Final Grid:**\n${drawBoard()}`);
        } else if (reason === "win") {
          finalEmbed.setDescription("Incredible! You have completely filled up the snake arena grid!");
        } else {
          finalEmbed.setDescription("The match timed out due to 15 minutes of inactivity.");
        }

        await gameMessage.edit({
          embeds: [finalEmbed],
          components: [disabledRow]
        }).catch(() => {});
      });
      return;
    }

    /* --- MESSAGES STATS --- */
    if (commandName === "messages") {
      const targetUser = interaction.options.getUser("user") || interaction.user;
      const targetMember = await interaction.guild.members.fetch(targetUser.id).catch(() => null);
      const stats = messageStats[targetUser.id] || { allTime: 0, monthly: 0, weekly: 0, today: 0 };
      const resets = getResetTimers();

      const embed = new EmbedBuilder()
        .setColor(0x2B2D31)
        .setTitle(`${targetMember?.displayName || targetUser.username}'s Messages`)
        .setThumbnail(targetUser.displayAvatarURL({ dynamic: true, size: 256 }))
        .setDescription(
          "❯ **Message Statistics**\n\n" +
          `**All Time** • \`${(stats.allTime || 0).toLocaleString()}\` messages\n` +
          `**This Month** • \`${(stats.monthly || 0).toLocaleString()}\` messages\n` +
          `**This Week** • \`${(stats.weekly || 0).toLocaleString()}\` messages\n` +
          `**Today** • \`${(stats.today || 0).toLocaleString()}\` messages\n\n` +
          "✦ **Next Reset**\n" +
          `Daily: \`${resets.daily}\` • Weekly: \`${resets.weekly}\` • Monthly: \`${resets.monthly}\`\n\n` +
          `*Your message statistics • <t:${Math.floor(Date.now() / 1000)}:R>*`
        );

      return interaction.reply({ embeds: [embed] });
    }

    /* --- AFK STATUS --- */
    if (commandName === "afk") {
      const reason = interaction.options.getString("reason") || "I am afk :)";

      afkData[interaction.user.id] = {
        isAfk: true,
        reason,
        since: Date.now(),
        mentions: []
      };
      saveAfkData();

      return interaction.reply({
        content: `You are now AFK for: **${reason}**`
      });
    }

    /* --- REAL-TIME LEADERBOARD --- */
    if (commandName === "leaderboard") {
      function generateLeaderboardEmbed(mode) {
        const medals = ["#1", "#2", "#3", "#4", "#5", "#6", "#7", "#8", "#9", "#10"];
        let listText = "";
        let userStandingText = "";

        if (mode === "daily") {
          const sorted = Object.entries(messageStats)
            .filter(([, d]) => (d.today || 0) > 0)
            .sort(([, a], [, b]) => (b.today || 0) - (a.today || 0));

          const top10 = sorted.slice(0, 10);
          listText = top10.length > 0
            ? top10.map(([id, d], i) => `${medals[i]} <@${id}> • **${(d.today || 0).toLocaleString()} Messages**`).join("\n\n")
            : "*No chat messages recorded today.*";

          const rankIdx = sorted.findIndex(([id]) => id === interaction.user.id);
          const userCount = messageStats[interaction.user.id]?.today || 0;
          const userRank = rankIdx !== -1 ? rankIdx + 1 : sorted.length + 1;
          userStandingText = `⭐ **Your Standing: #${userRank} of ${Math.max(sorted.length, 1)}** ${interaction.user} • **${userCount.toLocaleString()} Messages**`;
        } else {
          const sorted = Object.entries(levels)
            .sort(([, a], [, b]) => (b.level - a.level) || (b.xp - a.xp));

          const top10 = sorted.slice(0, 10);
          listText = top10.length > 0
            ? top10.map(([id, d], i) => `${medals[i]} <@${id}> • **Level ${d.level}** • **${(d.xp || 0).toLocaleString()} XP**`).join("\n\n")
            : "*No leveling data registered yet.*";

          const rankIdx = sorted.findIndex(([id]) => id === interaction.user.id);
          const userLvl = levels[interaction.user.id]?.level || 1;
          const userXp = levels[interaction.user.id]?.xp || 0;
          const userRank = rankIdx !== -1 ? rankIdx + 1 : sorted.length + 1;
          userStandingText = `⭐ **Your Standing: #${userRank} of ${Math.max(sorted.length, 1)}** ${interaction.user} • **Level ${userLvl} • ${userXp.toLocaleString()} XP**`;
        }

        return new EmbedBuilder()
          .setColor(0x00A8FC)
          .setTitle(mode === "daily" ? "💬 Daily Chat Leaderboard" : "XP & Level Leaderboard")
          .setDescription(
            "*The rankings are being updated in real-time!*\n\n" +
            listText + "\n\n" +
            "━━━━━━━━━━━━━━━━━━━━━━━━━━\n" +
            userStandingText
          )
          .setFooter({ text: "Page 1/1 | Real-Time Leaderboard" })
          .setTimestamp();
      }

      function getButtons(active) {
        return [
          new ActionRowBuilder().addComponents(
            new ButtonBuilder()
              .setCustomId("lb_levels")
              .setLabel("Top XP & Levels")
              .setEmoji("🏆")
              .setStyle(active === "levels" ? ButtonStyle.Primary : ButtonStyle.Secondary),
            new ButtonBuilder()
              .setCustomId("lb_daily")
              .setLabel("Daily Chat (Today)")
              .setEmoji("💬")
              .setStyle(active === "daily" ? ButtonStyle.Primary : ButtonStyle.Secondary)
          ),
          new ActionRowBuilder().addComponents(
            new ButtonBuilder()
              .setCustomId("lb_refresh")
              .setLabel("Refresh")
              .setEmoji("🔄")
              .setStyle(ButtonStyle.Secondary)
          )
        ];
      }

      let currentMode = interaction.options.getString("type") || "levels";
      const replyMsg = await interaction.reply({
        embeds: [generateLeaderboardEmbed(currentMode)],
        components: getButtons(currentMode),
        fetchReply: true
      });

      const collector = replyMsg.createMessageComponentCollector({
        filter: (i) => i.user.id === interaction.user.id,
        time: 5 * 60 * 1000
      });

      collector.on("collect", async (i) => {
        if (i.customId === "lb_levels") currentMode = "levels";
        if (i.customId === "lb_daily") currentMode = "daily";

        await i.update({
          embeds: [generateLeaderboardEmbed(currentMode)],
          components: getButtons(currentMode)
        }).catch(() => {});
      });

      collector.on("end", async () => {
        const disabledRows = getButtons(currentMode).map(row => {
          row.components.forEach(btn => btn.setDisabled(true));
          return row;
        });
        await replyMsg.edit({ components: disabledRows }).catch(() => {});
      });

      return;
    }
  }

  /* =========================================================
     VOICE CONTROL PANEL & TICKETS: DROPDOWN MENUS
  ========================================================= */
  if (interaction.isStringSelectMenu()) {

    /* --- 1. VOICE CONTROL PANEL DROPDOWNS --- */
    if (interaction.customId === "vc_settings_menu" || interaction.customId === "vc_permissions_menu") {
      const selected = interaction.values[0];
      const channel = interaction.member.voice.channel;

      if (!channel || !activeTempVoiceChannels.has(channel.id)) {
        return interaction.reply({
          content: "❌ You must be connected to your temporary voice channel to use this panel!",
          flags: MessageFlags.Ephemeral
        });
      }

      const currentOwnerId = tempVoiceOwners.get(channel.id);

      if (selected === "vc_claim") {
        if (currentOwnerId === interaction.user.id) {
          return interaction.reply({ content: "👑 You are already the owner of this voice channel!", flags: MessageFlags.Ephemeral });
        }

        const isOwnerStillInVC = channel.members.has(currentOwnerId);
        if (isOwnerStillInVC) {
          return interaction.reply({ content: "❌ You cannot claim ownership while the current owner is still inside the channel!", flags: MessageFlags.Ephemeral });
        }

        tempVoiceOwners.set(channel.id, interaction.user.id);
        await channel.permissionOverwrites.edit(interaction.user.id, {
          Connect: true,
          ManageChannels: true,
          MoveMembers: true
        });

        return interaction.reply({
          content: `👑 ${interaction.user} has successfully claimed ownership of this channel!`
        });
      }

      if (currentOwnerId !== interaction.user.id && !isGuildAdmin(interaction.member)) {
        return interaction.reply({
          content: "❌ Only the channel owner can modify channel settings and permissions!",
          flags: MessageFlags.Ephemeral
        });
      }

      if (selected === "vc_lock") {
        await channel.permissionOverwrites.edit(interaction.guild.id, { Connect: false });
        return interaction.reply({ content: "🔒 **Channel Locked:** Users can no longer join.", flags: MessageFlags.Ephemeral });
      }

      if (selected === "vc_unlock") {
        await channel.permissionOverwrites.edit(interaction.guild.id, { Connect: null });
        return interaction.reply({ content: "🔓 **Channel Unlocked:** Everyone can join.", flags: MessageFlags.Ephemeral });
      }

      if (selected === "vc_ghost") {
        await channel.permissionOverwrites.edit(interaction.guild.id, { ViewChannel: false });
        return interaction.reply({ content: "👻 **Channel Ghosted:** Your channel is now hidden from the server list.", flags: MessageFlags.Ephemeral });
      }

      if (selected === "vc_unghost") {
        await channel.permissionOverwrites.edit(interaction.guild.id, { ViewChannel: null });
        return interaction.reply({ content: "👁️ **Channel Visible:** Your channel is now visible to everyone.", flags: MessageFlags.Ephemeral });
      }

      if (selected === "vc_permit") {
        const userSelect = new UserSelectMenuBuilder()
          .setCustomId("vc_select_permit")
          .setPlaceholder("Select a user to permit into this channel")
          .setMaxValues(1);

        return interaction.reply({
          content: "Select the member you want to grant access to:",
          components: [new ActionRowBuilder().addComponents(userSelect)],
          flags: MessageFlags.Ephemeral
        });
      }

      if (selected === "vc_reject") {
        const userSelect = new UserSelectMenuBuilder()
          .setCustomId("vc_select_reject")
          .setPlaceholder("Select a user to disconnect / ban from VC")
          .setMaxValues(1);

        return interaction.reply({
          content: "Select the member you want to kick and block from this channel:",
          components: [new ActionRowBuilder().addComponents(userSelect)],
          flags: MessageFlags.Ephemeral
        });
      }

      if (selected === "vc_transfer") {
        const userSelect = new UserSelectMenuBuilder()
          .setCustomId("vc_select_transfer")
          .setPlaceholder("Select a user to transfer channel ownership to")
          .setMaxValues(1);

        return interaction.reply({
          content: "Select the member who will receive ownership:",
          components: [new ActionRowBuilder().addComponents(userSelect)],
          flags: MessageFlags.Ephemeral
        });
      }

      if (selected === "vc_name") {
        const modal = new ModalBuilder()
          .setCustomId("vc_modal_name")
          .setTitle("Change Channel Name");

        const input = new TextInputBuilder()
          .setCustomId("name_input")
          .setLabel("New Channel Name")
          .setStyle(TextInputStyle.Short)
          .setValue(channel.name)
          .setMaxLength(32)
          .setRequired(true);

        modal.addComponents(new ActionRowBuilder().addComponents(input));
        return interaction.showModal(modal);
      }

      if (selected === "vc_limit") {
        const modal = new ModalBuilder()
          .setCustomId("vc_modal_limit")
          .setTitle("Change User Limit");

        const input = new TextInputBuilder()
          .setCustomId("limit_input")
          .setLabel("User Limit (0 - 99, 0 for unlimited)")
          .setStyle(TextInputStyle.Short)
          .setValue(String(channel.userLimit || 0))
          .setMaxLength(2)
          .setRequired(true);

        modal.addComponents(new ActionRowBuilder().addComponents(input));
        return interaction.showModal(modal);
      }

      if (selected === "vc_status") {
        const modal = new ModalBuilder()
          .setCustomId("vc_modal_status")
          .setTitle("Change Channel Status");

        const input = new TextInputBuilder()
          .setCustomId("status_input")
          .setLabel("Voice Channel Status Text")
          .setStyle(TextInputStyle.Short)
          .setMaxLength(100)
          .setRequired(false);

        modal.addComponents(new ActionRowBuilder().addComponents(input));
        return interaction.showModal(modal);
      }

      if (selected === "vc_bitrate") {
        const modal = new ModalBuilder()
          .setCustomId("vc_modal_bitrate")
          .setTitle("Change Channel Bitrate");

        const input = new TextInputBuilder()
          .setCustomId("bitrate_input")
          .setLabel("Bitrate in kbps (e.g. 64, 96, 128, 256)")
          .setStyle(TextInputStyle.Short)
          .setValue(String(Math.round(channel.bitrate / 1000)))
          .setMaxLength(3)
          .setRequired(true);

        modal.addComponents(new ActionRowBuilder().addComponents(input));
        return interaction.showModal(modal);
      }
    }

    /* --- 2. SELECT MENU TICKETS --- */
    if (interaction.customId === "ticket_menu") {
      const type = interaction.values[0];
      const cfg = getGuildConfig(interaction.guild.id);
      const staffCfg = ensureStaffConfig(cfg);

      const permissionOverwrites = [
        {
          id: interaction.guild.id,
          deny: [PermissionsBitField.Flags.ViewChannel]
        },
        {
          id: interaction.user.id,
          allow: [
            PermissionsBitField.Flags.ViewChannel,
            PermissionsBitField.Flags.SendMessages,
            PermissionsBitField.Flags.ReadMessageHistory,
            PermissionsBitField.Flags.AttachFiles
          ]
        },
        {
          id: client.user.id,
          allow: [
            PermissionsBitField.Flags.ViewChannel,
            PermissionsBitField.Flags.SendMessages,
            PermissionsBitField.Flags.ManageChannels
          ]
        }
      ];

      const staffIds = new Set(Object.keys(staffCfg.users || {}));
      if (interaction.guild.ownerId) staffIds.add(interaction.guild.ownerId);

      for (const uid of staffIds) {
        if (interaction.guild.members.cache.has(uid)) {
          permissionOverwrites.push({
            id: uid,
            allow: [
              PermissionsBitField.Flags.ViewChannel,
              PermissionsBitField.Flags.SendMessages,
              PermissionsBitField.Flags.ReadMessageHistory,
              PermissionsBitField.Flags.AttachFiles
            ]
          });
        }
      }

      for (const rid of Object.values(staffCfg.roleLinks || {})) {
        if (rid && interaction.guild.roles.cache.has(rid)) {
          permissionOverwrites.push({
            id: rid,
            allow: [
              PermissionsBitField.Flags.ViewChannel,
              PermissionsBitField.Flags.SendMessages,
              PermissionsBitField.Flags.ReadMessageHistory,
              PermissionsBitField.Flags.AttachFiles
            ]
          });
        }
      }

      const channel = await interaction.guild.channels.create({
        name: `${type}-${interaction.user.username}`,
        type: ChannelType.GuildText,
        topic: buildTicketTopic({
          openerId: interaction.user.id,
          claimedById: null,
          status: "Unclaimed"
        }),
        permissionOverwrites
      });

      const embed = new EmbedBuilder()
        .setColor(0x8600FF)
        .setTitle(`🎫 ${interaction.guild.name} Support Ticket`)
        .setDescription(
          `Hello ${interaction.user}!\n\n` +
          `**Category:** \`${type.toUpperCase()}\`\n` +
          `**Status:** 🟡 Unclaimed\n\n` +
          `Please describe your issue or inquiry in detail.\nA staff member will assist you shortly.`
        )
        .setImage(BANNER)
        .setTimestamp();

      const row = new ActionRowBuilder().addComponents(
        new ButtonBuilder()
          .setCustomId("claim_ticket")
          .setLabel("Claim Ticket")
          .setEmoji("🙋‍♂️")
          .setStyle(ButtonStyle.Success),
        new ButtonBuilder()
          .setCustomId("close_ticket")
          .setLabel("Close Ticket")
          .setEmoji("🔒")
          .setStyle(ButtonStyle.Danger)
      );

      await channel.send({
        content: `${interaction.user} Welcome! Staff will be with you soon.`,
        embeds: [embed],
        components: [row]
      });

      return interaction.reply({
        content: `✅ Ticket created: ${channel}`,
        ephemeral: true
      });
    }
  }

  /* =========================================================
     VOICE CONTROL PANEL: MODAL SUBMISSIONS
  ========================================================= */
  if (interaction.isModalSubmit()) {
    const channel = interaction.member.voice.channel;
    if (!channel || !activeTempVoiceChannels.has(channel.id)) {
      return interaction.reply({ content: "❌ You are no longer in this voice channel.", flags: MessageFlags.Ephemeral });
    }

    if (interaction.customId === "vc_modal_name") {
      const newName = interaction.fields.getTextInputValue("name_input").trim();
      await channel.setName(newName).catch(() => {});
      return interaction.reply({ content: `✅ Channel name updated to: **${newName}**`, flags: MessageFlags.Ephemeral });
    }

    if (interaction.customId === "vc_modal_limit") {
      const val = parseInt(interaction.fields.getTextInputValue("limit_input"));
      if (isNaN(val) || val < 0 || val > 99) {
        return interaction.reply({ content: "❌ Please enter a valid number between 0 and 99.", flags: MessageFlags.Ephemeral });
      }
      await channel.setUserLimit(val).catch(() => {});
      return interaction.reply({ content: `👥 User limit updated to: **${val === 0 ? "Unlimited" : val}**`, flags: MessageFlags.Ephemeral });
    }

    if (interaction.customId === "vc_modal_status") {
      const newStatus = interaction.fields.getTextInputValue("status_input").trim();
      if (channel.setStatus) {
        await channel.setStatus(newStatus).catch(() => {});
      }
      return interaction.reply({ content: `💬 Status updated to: **${newStatus || "*Cleared*"}**`, flags: MessageFlags.Ephemeral });
    }

    if (interaction.customId === "vc_modal_bitrate") {
      const kbps = parseInt(interaction.fields.getTextInputValue("bitrate_input"));
      if (isNaN(kbps) || kbps < 8 || kbps > 384) {
        return interaction.reply({ content: "❌ Bitrate must be between 8 and 384 kbps.", flags: MessageFlags.Ephemeral });
      }
      await channel.setBitrate(kbps * 1000).catch(err => {
        return interaction.reply({ content: `❌ Could not set bitrate: ${err.message}`, flags: MessageFlags.Ephemeral });
      });
      return interaction.reply({ content: `🎚️ Bitrate updated to: **${kbps} kbps**`, flags: MessageFlags.Ephemeral });
    }
  }

  /* =========================================================
     VOICE CONTROL PANEL: USER SELECT HANDLERS
  ========================================================= */
  if (interaction.isUserSelectMenu()) {
    const channel = interaction.member.voice.channel;
    if (!channel || !activeTempVoiceChannels.has(channel.id)) {
      return interaction.reply({ content: "❌ You are no longer in this voice channel.", flags: MessageFlags.Ephemeral });
    }

    const targetId = interaction.values[0];

    if (interaction.customId === "vc_select_permit") {
      await channel.permissionOverwrites.edit(targetId, { Connect: true, ViewChannel: true });
      return interaction.update({ content: `✅ Access granted to <@${targetId}>!`, components: [] });
    }

    if (interaction.customId === "vc_select_reject") {
      if (targetId === interaction.user.id) {
        return interaction.update({ content: "❌ You cannot reject yourself!", components: [] });
      }
      const targetMember = await interaction.guild.members.fetch(targetId).catch(() => null);
      if (targetMember && targetMember.voice.channelId === channel.id) {
        await targetMember.voice.disconnect().catch(() => {});
      }
      await channel.permissionOverwrites.edit(targetId, { Connect: false });
      return interaction.update({ content: `🚫 <@${targetId}> has been disconnected and blocked from joining.`, components: [] });
    }

    if (interaction.customId === "vc_select_transfer") {
      if (targetId === interaction.user.id) {
        return interaction.update({ content: "❌ You already own this channel!", components: [] });
      }
      tempVoiceOwners.set(channel.id, targetId);
      await channel.permissionOverwrites.edit(targetId, {
        Connect: true,
        ManageChannels: true,
        MoveMembers: true
      });
      await interaction.update({ content: `👑 Transferred channel ownership to <@${targetId}>!`, components: [] });
      return channel.send(`👑 **Channel Ownership Update:** Ownership has been transferred to <@${targetId}>!`).catch(() => {});
    }
  }

  /* =========================
     BUTTON INTERACTIONS
  ========================= */
  if (interaction.isButton()) {

    /* --- CLAIM TICKET (OPEN TO ANY STAFF, LOCKED TO OTHERS AFTER CLAIM EXCEPT OWNER) --- */
    if (interaction.customId === "claim_ticket") {
      if (!canManageTickets(interaction.member)) {
        return interaction.reply({ content: "❌ Only server staff can claim tickets!", ephemeral: true });
      }

      const info = parseTicketTopic(interaction.channel.topic);
      const ownerCheck = isServerOwner(interaction.user, interaction.guild);

      if (info.claimedById && info.claimedById !== interaction.user.id && !ownerCheck) {
        return interaction.reply({
          content: `🔒 This ticket is already claimed by <@${info.claimedById}>. Only they or the **Server Owner** can intervene.`,
          ephemeral: true
        });
      }

      if (info.claimedById === interaction.user.id) {
        return interaction.reply({
          content: "⚠️ You have already claimed this ticket!",
          ephemeral: true
        });
      }

      await interaction.channel.setTopic(
        buildTicketTopic({
          openerId: info.openerId,
          claimedById: interaction.user.id,
          status: `Claimed by ${interaction.user.tag}`
        })
      ).catch(() => {});

      const cfg = getGuildConfig(interaction.guild.id);
      const staffCfg = ensureStaffConfig(cfg);

      for (const uid of Object.keys(staffCfg.users || {})) {
        if (uid !== interaction.user.id && uid !== info.openerId && uid !== interaction.guild.ownerId) {
          await interaction.channel.permissionOverwrites.edit(uid, {
            SendMessages: false
          }).catch(() => {});
        }
      }

      for (const rid of Object.values(staffCfg.roleLinks || {})) {
        if (rid && interaction.guild.roles.cache.has(rid)) {
          await interaction.channel.permissionOverwrites.edit(rid, {
            SendMessages: false
          }).catch(() => {});
        }
      }

      await interaction.channel.permissionOverwrites.edit(interaction.user.id, {
        ViewChannel: true,
        SendMessages: true,
        ReadMessageHistory: true,
        AttachFiles: true
      }).catch(() => {});

      const claimButton = new ButtonBuilder()
        .setCustomId("claimed_btn")
        .setLabel(`Claimed by ${interaction.user.username}`)
        .setEmoji("✅")
        .setStyle(ButtonStyle.Secondary)
        .setDisabled(true);

      const closeButton = new ButtonBuilder()
        .setCustomId("close_ticket")
        .setLabel("Close Ticket")
        .setEmoji("🔒")
        .setStyle(ButtonStyle.Danger);

      const updatedRow = new ActionRowBuilder().addComponents(claimButton, closeButton);
      await interaction.update({ components: [updatedRow] }).catch(() => {});

      return interaction.channel.send({
        content: `📌 **Ticket Claimed!** ${interaction.user} is now handling this ticket. Other staff are locked out unless elevated or intervened by the **Server Owner**. Use \`/elevate\` to escalate to **Owner** or **CEO**.`
      });
    }

    /* --- CLOSE TICKET WITH ADVANCED HTML TRANSCRIPT --- */
    if (interaction.customId === "close_ticket") {
      await interaction.reply({
        content: "📑 Generating transcript and closing ticket in **5 seconds**...",
        ephemeral: true
      });

      const fetchedMessages = await interaction.channel.messages.fetch({ limit: 100 });
      const sortedMessages = Array.from(fetchedMessages.values()).reverse();

      const ticketCreatedAt = interaction.channel.createdAt || new Date();
      const ticketClosedAt = new Date();
      const ticketId = interaction.channel.name.match(/\d+/)?.[0] || interaction.channel.id.slice(-4);

      const info = parseTicketTopic(interaction.channel.topic);
      const openerId = info.openerId || interaction.user.id;
      const openerUser = await client.users.fetch(openerId).catch(() => interaction.user);

      function escapeHtml(text) {
        if (!text) return "";
        return text
          .replace(/&/g, "&amp;")
          .replace(/</g, "&lt;")
          .replace(/>/g, "&gt;")
          .replace(/"/g, "&quot;")
          .replace(/'/g, "&#039;");
      }

      let messagesHtml = "";
      sortedMessages.forEach((m) => {
        const timeFormatted = new Date(m.createdTimestamp).toLocaleString("en-GB", {
          day: "2-digit",
          month: "2-digit",
          year: "numeric",
          hour: "2-digit",
          minute: "2-digit"
        }).replace(",", "");

        const avatarUrl = m.author.displayAvatarURL({ extension: "png", size: 128, forceStatic: false });
        let contentHtml = escapeHtml(m.content)
          .replace(/\n/g, "<br>")
          .replace(/&lt;@!?(\d+)&gt;/g, '<span class="mention">@User</span>');

        const isBot = m.author.bot;
        const appBadge = isBot ? '<span class="app-badge">APP</span>' : '';

        let embedsHtml = "";
        if (m.embeds.length > 0) {
          m.embeds.forEach((emb) => {
            const embedColor = emb.hexColor || "#5865f2";
            embedsHtml += `
              <div class="chat-embed" style="border-left-color: ${embedColor};">
                ${emb.title ? `<div class="embed-title">${escapeHtml(emb.title)}</div>` : ""}
                ${emb.description ? `<div class="embed-desc">${escapeHtml(emb.description).replace(/\n/g, "<br>")}</div>` : ""}
              </div>
            `;
          });
        }

        let attachmentsHtml = "";
        if (m.attachments.size > 0) {
          m.attachments.forEach((att) => {
            const isImage = att.contentType?.startsWith("image/") || /\.(png|jpe?g|gif|webp)$/i.test(att.name);
            if (isImage) {
              attachmentsHtml += `
                <div class="attachment-img">
                  <a href="${att.url}" target="_blank">
                    <img src="${att.url}" alt="${escapeHtml(att.name)}" />
                  </a>
                </div>
              `;
            } else {
              attachmentsHtml += `
                <div class="attachment-file">
                  <a href="${att.url}" target="_blank">📁 ${escapeHtml(att.name)}</a>
                </div>
              `;
            }
          });
        }

        messagesHtml += `
          <div class="chat-message">
            <img class="msg-avatar" src="${avatarUrl}" alt="${escapeHtml(m.author.username)}" />
            <div class="msg-body">
              <div class="msg-header">
                <span class="msg-author">${escapeHtml(m.author.username)}</span>
                ${appBadge}
                <span class="msg-timestamp">${timeFormatted}</span>
              </div>
              ${contentHtml ? `<div class="msg-text">${contentHtml}</div>` : ""}
              ${embedsHtml}
              ${attachmentsHtml}
            </div>
          </div>
        `;
      });

      const htmlContent = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>#${escapeHtml(interaction.channel.name)}</title>
  <style>
- { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: #313338;
      color: #dbdee1;
      font-family: 'gg sans', 'Noto Sans', 'Helvetica Neue', Helvetica, Arial, sans-serif;
      font-size: 15px;
      display: flex;
      flex-direction: column;
      min-height: 100vh;
    }
    .top-bar {
      height: 48px;
      background: #2b2d31;
      border-bottom: 1px solid #1f2023;
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 0 16px;
      position: sticky;
      top: 0;
      z-index: 10;
    }
    .top-title {
      font-weight: 600;
      color: #f2f3f5;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .top-title span.tag { color: #80848e; }
    .content-area {
      max-width: 1000px;
      width: 100%;
      margin: 0 auto;
      padding: 24px 16px;
      flex: 1;
    }
    .welcome-card {
      margin-bottom: 24px;
      padding-bottom: 16px;
      border-bottom: 1px solid #3f4147;
    }
    .welcome-card h1 {
      font-size: 28px;
      color: #f2f3f5;
      margin-bottom: 8px;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .welcome-card p {
      color: #949ba4;
      font-size: 14px;
    }
    .chat-message {
      display: flex;
      gap: 16px;
      padding: 6px 8px;
      margin-bottom: 6px;
      border-radius: 4px;
      transition: background 0.1s;
    }
    .chat-message:hover {
      background-color: #2e3035;
    }
    .msg-avatar {
      width: 40px;
      height: 40px;
      border-radius: 50%;
      flex-shrink: 0;
      background: #1e1f22;
    }
    .msg-body {
      flex: 1;
      overflow: hidden;
    }
    .msg-header {
      display: flex;
      align-items: center;
      gap: 8px;
      margin-bottom: 4px;
    }
    .msg-author {
      font-weight: 600;
      color: #f2f3f5;
      font-size: 15px;
    }
    .app-badge {
      background: #5865f2;
      color: #fff;
      font-size: 10px;
      font-weight: 700;
      padding: 1px 4px;
      border-radius: 3px;
      text-transform: uppercase;
    }
    .msg-timestamp {
      font-size: 12px;
      color: #949ba4;
    }
    .msg-text {
      color: #dbdee1;
      line-height: 1.4;
      word-break: break-word;
    }
    .mention {
      background: rgba(88, 101, 242, 0.2);
      color: #c9cdfb;
      padding: 1px 4px;
      border-radius: 3px;
      font-weight: 500;
    }
    .chat-embed {
      margin-top: 8px;
      background: #2b2d31;
      border-radius: 4px;
      border-left: 4px solid #5865f2;
      padding: 12px 16px;
      max-width: 520px;
    }
    .embed-title {
      font-weight: 700;
      color: #f2f3f5;
      margin-bottom: 6px;
    }
    .embed-desc {
      color: #dbdee1;
      font-size: 13px;
      line-height: 1.4;
    }
    .attachment-img img {
      max-width: 100%;
      max-height: 350px;
      border-radius: 8px;
      margin-top: 8px;
      display: block;
    }
    .attachment-file a {
      display: inline-block;
      margin-top: 6px;
      padding: 8px 12px;
      background: #2b2d31;
      color: #00a8fc;
      border-radius: 4px;
      text-decoration: none;
      font-size: 13px;
    }
    .transcript-footer {
      background: #232428;
      text-align: center;
      padding: 16px;
      color: #949ba4;
      font-size: 13px;
      border-top: 1px solid #1e1f22;
    }
    @media (max-width: 768px) {
      .content-area { padding: 16px 8px; }
      .welcome-card h1 { font-size: 22px; }
      .chat-message { gap: 10px; }
      .msg-avatar { width: 34px; height: 34px; }
      .chat-embed { max-width: 100%; }
    }
  </style>
</head>
<body>
  <div class="top-bar">
    <div class="top-title"><span class="tag">#</span> ${escapeHtml(interaction.channel.name)}</div>
    <div style="font-size: 13px; color: #949ba4;">${escapeHtml(interaction.guild.name)} Archive</div>
  </div>

  <div class="content-area">
    <div class="welcome-card">
      <h1>Welcome to #${escapeHtml(interaction.channel.name)}!</h1>
      <p>This is the start of the #${escapeHtml(interaction.channel.name)} channel transcript.</p>
    </div>

    ${messagesHtml}
  </div>

  <div class="transcript-footer">
    This transcript was generated on ${new Date().toUTCString()}
  </div>
</body>
</html>`;

      const transcriptBuffer = Buffer.from(htmlContent, "utf-8");
      const transcriptFile = new AttachmentBuilder(transcriptBuffer, {
        name: `transcript-${interaction.channel.name}.html`
      });

      const cfg = getGuildConfig(interaction.guild.id);
      const logChannel = cfg.channels.ticket ? client.channels.cache.get(cfg.channels.ticket) : null;
      let transcriptUrl = null;

      if (logChannel) {
        const uploadedMsg = await logChannel.send({ files: [transcriptFile] }).catch(console.error);
        transcriptUrl = uploadedMsg?.attachments?.first()?.url || null;

        const logEmbed = new EmbedBuilder()
          .setColor(0x2B2D31)
          .setTitle(`Ticket #${ticketId} Closed`)
          .addFields(
            { name: "🆔 ID", value: `\`${ticketId}\``, inline: true },
            { name: "🌐 Guild", value: interaction.guild.name, inline: true },
            { name: "👤 Creator", value: `${openerUser}`, inline: true },
            { name: "🔒 Closed By", value: `${interaction.user}`, inline: true },
            { name: "🕒 Created At", value: `<t:${Math.floor(ticketCreatedAt.getTime() / 1000)}:f>`, inline: true },
            { name: "🕒 Closed At", value: `<t:${Math.floor(ticketClosedAt.getTime() / 1000)}:f>`, inline: true },
            { name: "# Channel ID", value: `\`${interaction.channel.id}\``, inline: false },
            {
              name: "📜 Transcript",
              value: transcriptUrl ? `[Click to view transcript](${transcriptUrl})` : "*Archived as file*",
              inline: false
            }
          )
          .setFooter({ text: `Powered by ${interaction.guild.name}` })
          .setTimestamp();

        const row = new ActionRowBuilder();
        if (transcriptUrl) {
          row.addComponents(
            new ButtonBuilder()
              .setLabel("Transcript")
              .setStyle(ButtonStyle.Link)
              .setEmoji("📜")
              .setURL(transcriptUrl)
          );
        }

        if (uploadedMsg) {
          await uploadedMsg.edit({ embeds: [logEmbed], components: row.components.length ? [row] : [] }).catch(() => {});
        }
      }

      if (openerUser) {
        const dmEmbed = new EmbedBuilder()
          .setColor(0x2B2D31)
          .setTitle(`Ticket #${ticketId} Closed`)
          .setDescription(`Your ticket **#${interaction.channel.name}** in **${interaction.guild.name}** has been closed.`)
          .addFields(
            { name: "🔒 Closed By", value: `${interaction.user}`, inline: true },
            { name: "🕒 Closed At", value: `<t:${Math.floor(ticketClosedAt.getTime() / 1000)}:f>`, inline: true },
            {
              name: "📜 Transcript",
              value: transcriptUrl ? `[Click to view transcript](${transcriptUrl})` : "*Attached below*",
              inline: false
            }
          )
          .setFooter({ text: `Powered by ${interaction.guild.name}` })
          .setTimestamp();

        const dmRow = new ActionRowBuilder();
        if (transcriptUrl) {
          dmRow.addComponents(
            new ButtonBuilder()
              .setLabel("Transcript")
              .setStyle(ButtonStyle.Link)
              .setEmoji("📜")
              .setURL(transcriptUrl)
          );
        }

        const dmAttachment = new AttachmentBuilder(transcriptBuffer, {
          name: `transcript-${interaction.channel.name}.html`
        });

        await openerUser.send({
          embeds: [dmEmbed],
          components: dmRow.components.length ? [dmRow] : [],
          files: [dmAttachment]
        }).catch(() => {});
      }

      setTimeout(() => {
        interaction.channel.delete().catch(() => {});
      }, 5000);
      return;
    }

    /* --- GIVEAWAY ENTER BUTTON --- */
    if (interaction.customId === "giveaway_enter") {
      const gw = activeGiveaways.find((g) => g.messageId === interaction.message.id);
      if (!gw || gw.ended) {
        return interaction.reply({ content: "❌ This giveaway has ended.", ephemeral: true });
      }

      const userId = interaction.user.id;
      if (gw.entries.includes(userId)) {
        gw.entries = gw.entries.filter((id) => id !== userId);
        await interaction.reply({ content: "❌ You left the giveaway.", ephemeral: true });
      } else {
        gw.entries.push(userId);
        await interaction.reply({ content: "✅ You entered the giveaway! Good luck!", ephemeral: true });
      }

      saveGiveaways();

      const updatedButton = new ButtonBuilder()
        .setCustomId("giveaway_enter")
        .setLabel(`Enter (${gw.entries.length})`)
        .setEmoji("🎉")
        .setStyle(ButtonStyle.Success);

      const updatedRow = new ActionRowBuilder().addComponents(updatedButton);
      const updatedEmbed = EmbedBuilder.from(interaction.message.embeds[0])
        .setFooter({ text: `Entries: ${gw.entries.length} | Ends at` });

      return interaction.message.edit({ embeds: [updatedEmbed], components: [updatedRow] }).catch(() => {});
    }
  }
});

/* =========================
   INVITE TRACKING & WELCOME
========================= */
client.on("guildMemberAdd", async (member) => {
  const cfg = getGuildConfig(member.guild.id);

  // 1. Invite Tracking
  const guildInvites = await member.guild.invites.fetch().catch(() => {});
  if (guildInvites) {
    const cached = inviteCache.get(member.guild.id);
    let usedInvite = null;

    guildInvites.forEach((inv) => {
      const oldUses = cached?.get(inv.code) || 0;
      if (inv.uses > oldUses) {
        usedInvite = inv;
      }
    });

    const newCache = new Map();
    guildInvites.forEach((inv) => {
      newCache.set(inv.code, inv.uses);
    });
    inviteCache.set(member.guild.id, newCache);

    if (usedInvite && usedInvite.inviter) {
      const inviterId = usedInvite.inviter.id;

      if (!invites[inviterId]) {
        invites[inviterId] = createInviteData();
      }

      const data = invites[inviterId];
      const accountAge = Date.now() - member.user.createdTimestamp;
      const isFake = accountAge < 7 * 24 * 60 * 60 * 1000;

      data.total = (data.total || 0) + 1;

      if (isFake) {
        data.fake = (data.fake || 0) + 1;
      } else {
        data.current = (data.current || 0) + 1;
      }

      if (!Array.isArray(data.history)) {
        data.history = [];
      }

      data.history.push({
        user: member.id,
        inviter: inviterId,
        time: Date.now(),
        type: isFake ? "fake" : "real"
      });

      const logChannel = cfg.channels.invite ? client.channels.cache.get(cfg.channels.invite) : null;
      if (logChannel) {
        const inviterUser = client.users.cache.get(inviterId) || `<@${inviterId}>`;
        logChannel.send(
          `👤 ${inviterUser} invited **${member.user.tag}** (${member}) to the server and now has **${data.current}** invite(s)! ${isFake ? "⚠️ *(Suspected Fake Account)*" : ""}`
        ).catch(console.error);
      }

      saveInvites();
    }
  }

  // 2. Custom Welcome Message
  const welcomeChannel = cfg.channels.welcome
    ? await client.channels.fetch(cfg.channels.welcome).catch(() => null)
    : null;

  if (!welcomeChannel) return;

  const formattedWelcome = formatTemplate(cfg.messages.welcome, { member, guild: member.guild });
  const memberCount = member.guild.memberCount;

  const embed = new EmbedBuilder()
    .setColor(0x8600FF)
    .setAuthor({
      name: member.user.username,
      iconURL: member.user.displayAvatarURL()
    })
    .setTitle(`🎉 Welcome to ${member.guild.name}!`)
    .setDescription(
      `${formattedWelcome}\n\n` +
      `✨ We hope you enjoy your stay!`
    )
    .setThumbnail(member.user.displayAvatarURL({ dynamic: true }))
    .setImage(BANNER)
    .setFooter({
      text: `You are our #${memberCount} member!`
    })
    .setTimestamp();

  welcomeChannel.send({ content: `${member}`, embeds: [embed] }).catch(() => {});
});

/* =========================
   INVITE TRACKING REMOVE & GOODBYE
========================= */
client.on("guildMemberRemove", async (member) => {
  const cfg = getGuildConfig(member.guild.id);
  const memberId = member.id || member.user?.id;

  if (memberId) {
    for (const inviterId in invites) {
      if (!invites[inviterId]) continue;

      const data = invites[inviterId];
      if (!Array.isArray(data.history)) continue;

      const index = data.history.findIndex(
        h => String(h.user) === String(memberId)
      );

      if (index !== -1) {
        const record = data.history[index];

        if (record.type === "real") {
          data.current = Math.max(0, (data.current || 0) - 1);
          data.left = (data.left || 0) + 1;
        }

        if (record.type === "fake") {
          data.fake = Math.max(0, (data.fake || 0) - 1);
          data.left = (data.left || 0) + 1;
        }

        const logChannel = cfg.channels.invite ? client.channels.cache.get(cfg.channels.invite) : null;
        if (logChannel) {
          const username = member.user?.tag || member.displayName || "An unknown user";
          logChannel.send(
            `❌ **${username}** left the server. They were invited by <@${inviterId}>, whose remaining invite count is now **${data.current}**.`
          ).catch(console.error);
        }

        data.history.splice(index, 1);
        break;
      }
    }

    saveInvites();
  }

  // Custom Goodbye Message
  const goodbyeChannel = cfg.channels.goodbye
    ? await client.channels.fetch(cfg.channels.goodbye).catch(() => null)
    : null;

  if (!goodbyeChannel) return;

  const formattedGoodbye = formatTemplate(cfg.messages.goodbye, { member, guild: member.guild });

  const embed = new EmbedBuilder()
    .setColor(0xED4245)
    .setAuthor({
      name: member.user?.username || member.displayName,
      iconURL: member.user?.displayAvatarURL({ dynamic: true })
    })
    .setTitle(`👋 Goodbye from ${member.guild.name}`)
    .setDescription(
      `${formattedGoodbye}\n\n` +
      "💔 We're sad to see you go\n" +
      "🌍 You're always welcome back!"
    )
    .setThumbnail(member.user?.displayAvatarURL({ dynamic: true }))
    .setImage(BANNER)
    .setFooter({
      text: `We now have ${member.guild.memberCount} members...`
    })
    .setTimestamp();

  goodbyeChannel.send({ embeds: [embed] }).catch(() => {});
});

/* =========================
   SERVER BOOST MESSAGE
========================= */
client.on("guildMemberUpdate", async (oldMember, newMember) => {
  if (!oldMember.premiumSince && newMember.premiumSince) {
    const cfg = getGuildConfig(newMember.guild.id);
    const channel = cfg.channels.boost
      ? await client.channels.fetch(cfg.channels.boost).catch(() => null)
      : null;

    if (!channel) return;

    const formattedBoost = formatTemplate(cfg.messages.boost, { member: newMember, guild: newMember.guild });

    const embed = new EmbedBuilder()
      .setColor(0xFF73FA)
      .setTitle("🚀 New Server Boost!")
      .setDescription(
        `${formattedBoost}\n\n` +
        `Your support helps us improve **${newMember.guild.name}**, unlock new perks, and keep the community growing stronger every day.\n\n` +
        `✨ We truly appreciate your support and generosity!`
      )
      .setThumbnail(newMember.user.displayAvatarURL({ dynamic: true }))
      .setImage(BANNER)
      .setFooter({
        text: `${newMember.guild.name} Booster System`
      })
      .setTimestamp();

    channel.send({
      content: `🎉 ${newMember} just boosted the server!`,
      embeds: [embed]
    }).catch(() => {});
  }
});

/* =========================
   JOIN TO CREATE / TEMP VOICE
========================= */
client.on("voiceStateUpdate", async (oldState, newState) => {
  const { member, guild } = newState;
  if (!guild) return;

  const cfg = getGuildConfig(guild.id);

  // 1. User joins the configured "Join to Create" voice channel
  if (cfg.channels.jtc && newState.channelId === cfg.channels.jtc) {
    try {
      const parentCategory = newState.channel.parent;

      const tempChannel = await guild.channels.create({
        name: `🔊・${member.displayName}'s VC`,
        type: ChannelType.GuildVoice,
        parent: parentCategory || null,
        position: newState.channel.rawPosition + 1,
        permissionOverwrites: [
          {
            id: guild.id,
            allow: [PermissionsBitField.Flags.Connect, PermissionsBitField.Flags.ViewChannel]
          },
          {
            id: member.id,
            allow: [
              PermissionsBitField.Flags.Connect,
              PermissionsBitField.Flags.ViewChannel,
              PermissionsBitField.Flags.ManageChannels,
              PermissionsBitField.Flags.MoveMembers,
              PermissionsBitField.Flags.MuteMembers
            ]
          }
        ]
      });

      activeTempVoiceChannels.add(tempChannel.id);
      tempVoiceOwners.set(tempChannel.id, member.id);

      await newState.setChannel(tempChannel);

      const panelEmbed = new EmbedBuilder()
        .setColor(0x2B2D31)
        .setTitle("⚙️ Welcome to your own temporary voice channel")
        .setDescription(
          "Control your channel using the menus below\n" +
          "• Use the dropdowns to manage settings and permissions\n" +
          "• Only the channel owner can adjust these controls\n" +
          "• If the owner leaves, anyone inside can use **Claim** to take ownership!\n\n" +
          `👑 **Channel Owner:** ${member} (\`${member.displayName}\`)`
        )
        .setThumbnail(member.user.displayAvatarURL({ dynamic: true }))
        .setFooter({ text: "VoiceMaster • Temp Voice Control" });

      const settingsRow = new ActionRowBuilder().addComponents(
        new StringSelectMenuBuilder()
          .setCustomId("vc_settings_menu")
          .setPlaceholder("Change channel settings")
          .addOptions([
            { label: "Name", description: "Change the channel name", emoji: "🪪", value: "vc_name" },
            { label: "Limit", description: "Change the channel user limit", emoji: "👥", value: "vc_limit" },
            { label: "Status", description: "Change the channel status text", emoji: "💬", value: "vc_status" },
            { label: "Bitrate", description: "Change the channel voice bitrate", emoji: "🎚️", value: "vc_bitrate" },
            { label: "Claim", description: "Claim ownership of the channel", emoji: "👑", value: "vc_claim" }
          ])
      );

      const permissionsRow = new ActionRowBuilder().addComponents(
        new StringSelectMenuBuilder()
          .setCustomId("vc_permissions_menu")
          .setPlaceholder("Change channel permissions")
          .addOptions([
            { label: "Lock", description: "Lock the channel for everyone", emoji: "🔒", value: "vc_lock" },
            { label: "Unlock", description: "Unlock the channel for everyone", emoji: "🔓", value: "vc_unlock" },
            { label: "Ghost", description: "Make your channel invisible", emoji: "👻", value: "vc_ghost" },
            { label: "Unghost", description: "Make your channel visible", emoji: "👁️", value: "vc_unghost" },
            { label: "Permit", description: "Permit a user/friend to access", emoji: "✅", value: "vc_permit" },
            { label: "Reject", description: "Disconnect & block a user", emoji: "🚫", value: "vc_reject" },
            { label: "Transfer", description: "Transfer ownership to another user", emoji: "👑", value: "vc_transfer" }
          ])
      );

      await tempChannel.send({
        content: `${member}`,
        embeds: [panelEmbed],
        components: [settingsRow, permissionsRow]
      }).catch(() => {});
    } catch (err) {
      console.error("Error creating temp voice channel:", err);
    }
  }

  // 2. Member leaves temporary voice channel -> Auto delete if empty
  if (oldState.channelId && activeTempVoiceChannels.has(oldState.channelId)) {
    const channel = oldState.channel;
    if (channel && channel.members.size === 0) {
      activeTempVoiceChannels.delete(channel.id);
      tempVoiceOwners.delete(channel.id);
      await channel.delete().catch(() => {});
    }
  }
});

/* =========================
   ANTI-NUKE EVENT LISTENERS
========================= */
client.on("channelDelete", async (channel) => {
  if (!channel.guild) return;

  try {
    const fetchedLogs = await channel.guild.fetchAuditLogs({
      limit: 1,
      type: AuditLogEvent.ChannelDelete
    });
    const entry = fetchedLogs.entries.first();
    if (!entry || !entry.executor) return;

    if (Date.now() - entry.createdTimestamp > 5000) return;

    const count = recordNukeAction(entry.executor.id, "channelDeletes");
    if (count >= NUKE_LIMITS.CHANNEL_DELETE) {
      await triggerNukeDefense(channel.guild, entry.executor, "Channel Deletions", count);
    }
  } catch (err) {
    console.error("Error inspecting channelDelete audit log:", err);
  }
});

client.on("roleDelete", async (role) => {
  if (!role.guild) return;

  try {
    const fetchedLogs = await role.guild.fetchAuditLogs({
      limit: 1,
      type: AuditLogEvent.RoleDelete
    });
    const entry = fetchedLogs.entries.first();
    if (!entry || !entry.executor) return;

    if (Date.now() - entry.createdTimestamp > 5000) return;

    const count = recordNukeAction(entry.executor.id, "roleDeletes");
    if (count >= NUKE_LIMITS.ROLE_DELETE) {
      await triggerNukeDefense(role.guild, entry.executor, "Role Deletions", count);
    }
  } catch (err) {
    console.error("Error inspecting roleDelete audit log:", err);
  }
});

client.on("guildBanAdd", async (ban) => {
  try {
    const fetchedLogs = await ban.guild.fetchAuditLogs({
      limit: 1,
      type: AuditLogEvent.MemberBanAdd
    });
    const entry = fetchedLogs.entries.first();
    if (!entry || !entry.executor) return;

    if (Date.now() - entry.createdTimestamp > 5000) return;

    const count = recordNukeAction(entry.executor.id, "memberBans");
    if (count >= NUKE_LIMITS.MEMBER_BAN) {
      await triggerNukeDefense(ban.guild, entry.executor, "Mass Member Bans", count);
    }
  } catch (err) {
    console.error("Error inspecting guildBanAdd audit log:", err);
  }
});

/* =========================
   AUDIT LOGS: MESSAGE DELETE
========================= */
client.on("messageDelete", async (message) => {
  if (!message.guild || message.author?.bot) return;
  if (MONITORED_CHANNEL_ID && message.channel.id !== MONITORED_CHANNEL_ID) return;

  const cfg = getGuildConfig(message.guild.id);
  const logChannel = cfg.channels.audit ? message.guild.channels.cache.get(cfg.channels.audit) : null;
  if (!logChannel) return;

  const content = message.content ? message.content.slice(0, 1000) : "*No text content (Embed or Attachment only)*";
  const attachments = message.attachments.size > 0
    ? message.attachments.map((a) => a.url).join("\n")
    : null;

  const deleteEmbed = new EmbedBuilder()
    .setColor(0xED4245)
    .setAuthor({
      name: message.author?.tag || "Unknown User",
      iconURL: message.author?.displayAvatarURL({ dynamic: true })
    })
    .setTitle("🗑️ Message Deleted")
    .setDescription(
      `**Author:** ${message.author || "Unknown"} (\`${message.author?.id || "N/A"}\`)\n` +
      `**Channel:** ${message.channel} (\`${message.channel.id}\`)\n\n` +
      `**Content:**\n\`\`\`\n${content}\n\`\`\`` +
      (attachments ? `\n**Attachments:**\n${attachments}` : "")
    )
    .setFooter({ text: `Message ID: ${message.id}` })
    .setTimestamp();

  await logChannel.send({ embeds: [deleteEmbed] }).catch(() => {});
});

/* =========================
   AUDIT LOGS: MESSAGE EDIT
========================= */
client.on("messageUpdate", async (oldMessage, newMessage) => {
  if (!newMessage.guild || newMessage.author?.bot) return;
  if (MONITORED_CHANNEL_ID && newMessage.channel.id !== MONITORED_CHANNEL_ID) return;
  if (oldMessage.content === newMessage.content) return;

  const cfg = getGuildConfig(newMessage.guild.id);
  const logChannel = cfg.channels.audit ? newMessage.guild.channels.cache.get(cfg.channels.audit) : null;
  if (!logChannel) return;

  const oldText = oldMessage.content ? oldMessage.content.slice(0, 900) : "*Original content uncached*";
  const newText = newMessage.content ? newMessage.content.slice(0, 900) : "*Empty content*";

  const editEmbed = new EmbedBuilder()
    .setColor(0x5865F2)
    .setAuthor({
      name: newMessage.author.tag,
      iconURL: newMessage.author.displayAvatarURL({ dynamic: true })
    })
    .setTitle("✏️ Message Edited")
    .setDescription(
      `**Author:** ${newMessage.author} (\`${newMessage.author.id}\`)\n` +
      `**Channel:** ${newMessage.channel} (\`${newMessage.channel.id}\`)\n` +
      `**Jump to Message:** [Click Here](${newMessage.url})\n\n` +
      `**Before:**\n\`\`\`\n${oldText}\n\`\`\`\n` +
      `**After:**\n\`\`\`\n${newText}\n\`\`\``
    )
    .setFooter({ text: `Message ID: ${newMessage.id}` })
    .setTimestamp();

  await logChannel.send({ embeds: [editEmbed] }).catch(() => {});
});

/* =========================
   LOGIN & MEMORY PURGE
========================= */
const bootToken = process.env.DISCORD_TOKEN;

client.login(bootToken).then(() => {
  delete process.env.DISCORD_TOKEN;
  Object.freeze(process.env);
  console.log("🛡️ [SECURITY] Bot logged in. Token purged from runtime memory.");
}).catch((err) => {
  console.error("Login failed:", err);
});
