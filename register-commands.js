'use strict';

const { REST, Routes, SlashCommandBuilder, PermissionFlagsBits } = require('discord.js');
require('dotenv').config();

const { DISCORD_TOKEN, CLIENT_ID, GUILD_ID } = process.env;
if (!DISCORD_TOKEN || !CLIENT_ID) {
  console.error('Missing DISCORD_TOKEN or CLIENT_ID in .env');
  process.exit(1);
}

const SOURCE_OPTIONS = (b) => b
  .addStringOption(o => o.setName('code').setDescription('Paste code directly').setRequired(false))
  .addAttachmentOption(o => o.setName('file').setDescription('Upload a .lua/.luau/.txt file').setRequired(false))
  .addStringOption(o => o.setName('url').setDescription('Raw URL to fetch source from').setRequired(false));

const commands = [
  new SlashCommandBuilder().setName('help').setDescription('Show command list'),

  new SlashCommandBuilder()
    .setName('cfg')
    .setDescription('View or toggle your config')
    .addStringOption(o => o.setName('setting').setDescription('Which setting').setRequired(false)
      .addChoices(
        { name: 'View current config', value: 'view' },
        { name: 'Toggle Hook OP', value: 'hookop' },
        { name: 'Toggle Debug Dumper', value: 'debug' },
      )),

  SOURCE_OPTIONS(new SlashCommandBuilder().setName('env').setDescription('Dump script/environment output as a .log file')),
  SOURCE_OPTIONS(new SlashCommandBuilder().setName('get').setDescription('Fetch raw source as a .lua file')),
  SOURCE_OPTIONS(new SlashCommandBuilder().setName('beautify').setDescription('Beautify Lua/txt source')),

  new SlashCommandBuilder()
    .setName('deobf')
    .setDescription('Deobfuscate a script')
    .addStringOption(o => o.setName('engine').setDescription('Start typing to search engines').setRequired(true).setAutocomplete(true))
    .addStringOption(o => o.setName('code').setDescription('Paste code directly').setRequired(false))
    .addAttachmentOption(o => o.setName('file').setDescription('Upload a .lua/.luau/.txt file').setRequired(false))
    .addStringOption(o => o.setName('url').setDescription('Raw URL to fetch source from').setRequired(false)),

  SOURCE_OPTIONS(new SlashCommandBuilder()
    .setName('extract')
    .setDescription('Extract loadstrings, strings, URLs, constants, remotes')
    .addStringOption(o => o.setName('type').setDescription('What to extract').setRequired(false)
      .addChoices(
        { name: 'Everything (default)', value: 'all' },
        { name: 'loadstring payloads', value: 'loadstring' },
        { name: 'All strings', value: 'strings' },
        { name: 'URLs only', value: 'urls' },
        { name: 'Constants', value: 'constants' },
        { name: 'Remotes', value: 'remotes' },
      ))),

  SOURCE_OPTIONS(new SlashCommandBuilder().setName('cascade').setDescription('Run multiple engines and return the best result')),

  new SlashCommandBuilder()
    .setName('whitelist').setDescription('(Owner) Add a user to the whitelist')
    .setDefaultMemberPermissions(PermissionFlagsBits.Administrator)
    .addUserOption(o => o.setName('user').setDescription('User to whitelist').setRequired(true)),

  new SlashCommandBuilder()
    .setName('unwhitelist').setDescription('(Owner) Remove a user from the whitelist')
    .setDefaultMemberPermissions(PermissionFlagsBits.Administrator)
    .addUserOption(o => o.setName('user').setDescription('User to remove').setRequired(true)),

  new SlashCommandBuilder()
    .setName('whitelisted').setDescription('(Owner) List all whitelisted users')
    .setDefaultMemberPermissions(PermissionFlagsBits.Administrator),
].map(c => c.toJSON());

const rest = new REST({ version: '10' }).setToken(DISCORD_TOKEN);

(async () => {
  try {
    if (GUILD_ID) {
      console.log(`Registering ${commands.length} commands to guild ${GUILD_ID}...`);
      await rest.put(Routes.applicationGuildCommands(CLIENT_ID, GUILD_ID), { body: commands });
    } else {
      console.log(`Registering ${commands.length} commands globally (may take up to 1 hour to propagate)...`);
      await rest.put(Routes.applicationCommands(CLIENT_ID), { body: commands });
    }
    console.log('Commands registered successfully.');
  } catch (e) {
    console.error('Registration failed:', e);
    process.exit(1);
  }
})();
