# Onyx user guide

A short guide for someone who wants to use Onyx, not study it. No background
in cryptography needed.

## Before you start

Onyx is a small project by one person. It has not been checked by outside
security experts. It tries hard to keep your conversations private, but it
may have mistakes nobody has found yet.

So: enjoy it, try it with friends, tell us what breaks. Please do not rely on
it for anything where being exposed could get you hurt, arrested, or fired.
For that, use Signal.

## What Onyx is

A chat program that runs in your terminal.

- There is no account, no phone number, no email. Nobody signs you up.
- Messages go straight from your computer to your friend's, through the Tor
  network, which hides where each of you is.
- Only you and the person you are talking to can read the messages.
- There is no company server in the middle. If your friend is offline, the
  message waits on your computer until they come back.

## Install

```sh
curl -fsSL https://github.com/albinvar/onyx/releases/latest/download/install.sh | bash
```

Works on macOS and Linux. On Windows, use WSL2. If you would rather read the
script before running it (a good habit), see `INSTALL.md`.

## First run

```sh
onyx
```

1. **Choose a passphrase.** It locks your keys and messages on this computer.
   There is no "forgot my passphrase" — if you lose it, the data is gone. Pick
   something long that you will remember.
2. **Wait about a minute.** The top line will say Tor is starting, then ready.
   The first start is the slowest.

That's it. You are running.

## Add a friend

You each need the other's *connect code* once. Both of you should have Onyx
open.

**You:** press `Ctrl-E`, then `Enter` to copy the connect code.

If nothing lands in your clipboard — this is normal when you run Onyx on
another machine over SSH — press `p`. Onyx steps aside and shows the code as
plain text you can select with the mouse. Any key brings Onyx back.

**Send it to your friend** some way you already trust — in person, or in a
chat where you are sure it is really them. Anyone who gets this code can
reach you, so don't post it publicly.

**Your friend:** presses `Ctrl-A`, pastes the code, presses `Enter`.

After a few seconds (sometimes up to a minute or two — Tor is slow) they
appear in your list with a filled dot `●`. You can chat.

### Check it is really them

The first time, do this once: type `/verify` in the conversation. Onyx shows
a short number. Read it to your friend over a call or in person. If you both
see the same number, nobody is sitting in between.

If Onyx ever says a friend's **identity changed**, stop. It usually means
they reinstalled. It could mean someone is pretending to be them. Ask them
another way before you carry on.

## Chatting

- `↑` `↓` to pick a conversation. Type. `Enter` to send.
- `●` means your friend is connected right now. `○` means they are not.
- If they are offline, your message waits on your computer and is sent when
  they come back. If you use a hub, it is left at the hub instead (locked, so
  the hub cannot read it), which means it arrives even if you are offline by
  then.
- When a message reaches your friend, their Onyx quietly tells yours. That
  also tells them you were online. To stop sending these yourself, type
  `/receipts off`.
- `PgUp` / `PgDn` to scroll back. `End` to return to the newest message.

## Group chats (rooms)

- `Ctrl-N` — make a room and give it a name.
- `Ctrl-I` — invite a friend into the room you have selected.

Without a *hub*, a room message only reaches members who are connected to
you at that moment. With one, members who are away get it later (see below).
The person who made the room is its admin and decides who joins.

If someone you have **not** added as a friend invites you to a room, Onyx does
not join it for you. It holds the invitation and tells you. To answer, type
one of these where you would type a message:

```
/invites        see what is waiting
/join 1         join invitation number 1
/decline 1      throw it away
```

## Sending files

`Ctrl-F`, pick a file, `Enter`. Onyx removes hidden details from photos (like
where and when they were taken) before sending, unless you tell it not to.

Files you receive are saved under `~/.onyx/files/`. Treat a file from Onyx
like a file from anywhere else: think before opening it.

## Hubs, in one minute

By default Onyx uses no middleman at all. That is the most private setup, but
both people must be online at the same time for a first hello, and rooms need
somewhere to leave messages for members who are away.

A **hub** is a small relay that holds locked messages until the other person
picks them up. It cannot read them and cannot tell who wrote them. It *can*
see that something arrived and when — so it is a little less private than no
hub. You choose whether to use one: `Ctrl-G` in the chat screen.

## When something doesn't work

Close the chat screen and run:

```sh
onyx doctor
```

It checks the usual suspects and tells you in plain words what is wrong.

Common ones:

| What you see | What it usually means |
|---|---|
| Friend stays `○` | They are offline, or Tor is having a slow moment. Give it a couple of minutes. |
| "Tor starting" for a long time | Slow network. If Tor is blocked where you are, see `TOR-BRIDGES.md`. |
| Onyx will not start, says the vault is locked | It is already running in another window. |
| Wrong passphrase | It cannot be recovered. Sorry — that is the price of nobody else being able to open it either. |

Press `F1` in the chat screen any time to see every key.

## Keeping yourself safe

Onyx can protect messages while they travel. It cannot protect you from
everything. A few honest points:

- **Your computer matters most.** If someone can use your unlocked computer,
  or it has malware, they see what you see.
- **Your friends can tell when you are online.** So can anyone they pass your
  connect code to. Share it carefully.
- **Messages you send can be kept.** The other person can screenshot, copy,
  or show them to someone else.
- **Using Tor is visible.** Your internet provider can see that you use Tor,
  though not what for.
- **Back up.** `onyx vault backup` (with Onyx closed) saves a copy. Keep it
  somewhere safe; it is still locked with your passphrase.

## Quitting and removing

`Esc` or `Ctrl-C` quits.

To remove Onyx and everything it stored, delete the program
(`~/.local/bin/onyx`) and the folder `~/.onyx`. This cannot be undone.

## Want to know more?

- `README.md` — all commands and options.
- `HOW_IT_WORKS.md` — how the protection works, in plain language.
- `ATTACKS.md` — known ways systems like this have been broken, and where
  Onyx stands on each.

Found a bug or something confusing? Open an issue on GitHub. If it looks like
a security problem, please report it privately (see `SECURITY.md`).
