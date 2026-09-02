import concurrent.futures
import threading
from reconx.core.engine import Module
from reconx.utils.http import check_username_url
from reconx.utils.output import print_found, print_not_found, print_error, print_info


SITES = [
    {
        "name": "GitHub",
        "url": "https://github.com/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Twitter / X",
        "url": "https://twitter.com/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Instagram",
        "url": "https://www.instagram.com/{username}/",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Reddit",
        "url": "https://www.reddit.com/user/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "TikTok",
        "url": "https://www.tiktok.com/@{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "YouTube",
        "url": "https://www.youtube.com/@{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "LinkedIn",
        "url": "https://www.linkedin.com/in/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Facebook",
        "url": "https://www.facebook.com/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Pinterest",
        "url": "https://www.pinterest.com/{username}/",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Twitch",
        "url": "https://www.twitch.tv/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Snapchat",
        "url": "https://www.snapchat.com/add/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Medium",
        "url": "https://medium.com/@{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Dev.to",
        "url": "https://dev.to/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "GitLab",
        "url": "https://gitlab.com/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Bitbucket",
        "url": "https://bitbucket.org/{username}/",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Docker Hub",
        "url": "https://hub.docker.com/u/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "npm",
        "url": "https://www.npmjs.com/~{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "PyPI",
        "url": "https://pypi.org/user/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Steam",
        "url": "https://steamcommunity.com/id/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Spotify",
        "url": "https://open.spotify.com/user/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "SoundCloud",
        "url": "https://soundcloud.com/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Flickr",
        "url": "https://www.flickr.com/people/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Vimeo",
        "url": "https://vimeo.com/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "About.me",
        "url": "https://about.me/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Gravatar",
        "url": "https://gravatar.com/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Keybase",
        "url": "https://keybase.io/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Hacker News",
        "url": "https://news.ycombinator.com/user?id={username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Stack Overflow",
        "url": "https://stackoverflow.com/users/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "HackerOne",
        "url": "https://hackerone.com/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Bugcrowd",
        "url": "https://bugcrowd.com/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Lichess",
        "url": "https://lichess.org/@/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Chess.com",
        "url": "https://www.chess.com/member/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Patreon",
        "url": "https://www.patreon.com/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "BuyMeACoffee",
        "url": "https://www.buymeacoffee.com/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Ko-fi",
        "url": "https://ko-fi.com/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Substack",
        "url": "https://{username}.substack.com",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "WordPress",
        "url": "https://{username}.wordpress.com",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Tumblr",
        "url": "https://{username}.tumblr.com",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Blogger",
        "url": "https://{username}.blogspot.com",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "DeviantArt",
        "url": "https://www.deviantart.com/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Foursquare",
        "url": "https://foursquare.com/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Letterboxd",
        "url": "https://letterboxd.com/{username}/",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Goodreads",
        "url": "https://www.goodreads.com/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Last.fm",
        "url": "https://www.last.fm/user/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Trello",
        "url": "https://trello.com/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "SlideShare",
        "url": "https://www.slideshare.net/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Pastebin",
        "url": "https://pastebin.com/u/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Replit",
        "url": "https://replit.com/@{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "CodePen",
        "url": "https://codepen.io/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "JSFiddle",
        "url": "https://jsfiddle.net/user/{username}/",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Mastodon",
        "url": "https://mastodon.social/@{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Discord",
        "url": "https://discord.com/users/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Telegram",
        "url": "https://t.me/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "X (Twitter) API",
        "url": "https://nitter.net/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Quora",
        "url": "https://www.quora.com/profile/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Archive.org",
        "url": "https://archive.org/details/@{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Cracked.to",
        "url": "https://cracked.to/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "0x00sec",
        "url": "https://0x00sec.org/u/{username}/summary",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Hack The Box",
        "url": "https://app.hackthebox.com/profile/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "TryHackMe",
        "url": "https://tryhackme.com/p/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "OpenSea",
        "url": "https://opensea.io/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Etsy",
        "url": "https://www.etsy.com/shop/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Untappd",
        "url": "https://untappd.com/user/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "TripAdvisor",
        "url": "https://www.tripadvisor.com/Profile/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Yelp",
        "url": "https://www.yelp.com/user_details?userid={username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Amazon",
        "url": "https://www.amazon.com/gp/profile/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "eBay",
        "url": "https://www.ebay.com/usr/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Wikipedia",
        "url": "https://en.wikipedia.org/wiki/User:{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Wikidata",
        "url": "https://www.wikidata.org/wiki/User:{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Imgur",
        "url": "https://imgur.com/user/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "VirusTotal",
        "url": "https://www.virustotal.com/ui/users/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Shodan",
        "url": "https://www.shodan.io/user/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Censys",
        "url": "https://search.censys.io/profiles/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Have I Been Pwned",
        "url": "https://haveibeenpwned.com",
        "check_type": "custom",
    },
    {
        "name": "GitHub Gist",
        "url": "https://gist.github.com/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Packer",
        "url": "https://packer.io/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "SourceForge",
        "url": "https://sourceforge.net/u/{username}/profile",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Kaggle",
        "url": "https://www.kaggle.com/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Adobe Portfolio",
        "url": "https://{username}.myportfolio.com",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Behance",
        "url": "https://www.behance.net/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Dribbble",
        "url": "https://dribbble.com/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Figma",
        "url": "https://www.figma.com/@{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Clubhouse",
        "url": "https://www.clubhouse.com/@{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Periscope",
        "url": "https://www.pscp.tv/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Mixcloud",
        "url": "https://www.mixcloud.com/{username}/",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Bandcamp",
        "url": "https://{username}.bandcamp.com",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Kick",
        "url": "https://kick.com/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Rumble",
        "url": "https://rumble.com/user/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Threads",
        "url": "https://www.threads.net/@{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Bluesky",
        "url": "https://bsky.app/profile/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Mastodon (mastodon.social)",
        "url": "https://mastodon.social/@{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "PerfCast",
        "url": "https://perfcast.cc/u/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Rajce",
        "url": "https://{username}.rajce.idnes.cz/",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Launchpad",
        "url": "https://launchpad.net/~{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "OSF",
        "url": "https://osf.io/{username}/",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Cloudflare",
        "url": "https://www.cloudflare.com",
        "check_type": "custom",
    },
    {
        "name": "Product Hunt",
        "url": "https://www.producthunt.com/@{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Crew",
        "url": "https://www.crew.co/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Angellist",
        "url": "https://wellfound.com/u/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Investing.com",
        "url": "https://www.investing.com/traders/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Cash.app",
        "url": "https://cash.app/${username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Venmo",
        "url": "https://venmo.com/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Gumroad",
        "url": "https://{username}.gumroad.com",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Loom",
        "url": "https://www.loom.com/@{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Notion",
        "url": "https://www.notion.so/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Carrd",
        "url": "https://{username}.carrd.co",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Linktree",
        "url": "https://linktr.ee/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Beacons",
        "url": "https://beacons.ai/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Muck Rack",
        "url": "https://muckrack.com/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Musescore",
        "url": "https://musescore.com/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Genius",
        "url": "https://genius.com/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Animoto",
        "url": "https://animoto.com/play/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Channel Meter",
        "url": "https://channelmeter.com/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Jekyll",
        "url": "https://{username}.github.io",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Ringory",
        "url": "https://ringory.com/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Cent.co",
        "url": "https://cent.co/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "F6S",
        "url": "https://www.f6s.com/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Freelancer",
        "url": "https://www.freelancer.com/u/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Upwork",
        "url": "https://www.upwork.com/freelancers/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Fiverr",
        "url": "https://www.fiverr.com/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "PeoplePerHour",
        "url": "https://www.peopleperhour.com/freelancer/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Guru",
        "url": "https://www.guru.com/d/freelancers/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "9GAG",
        "url": "https://9gag.com/u/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "iNaturalist",
        "url": "https://www.inaturalist.org/people/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Roblox",
        "url": "https://www.roblox.com/users/profile?username={username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Spotify (artist)",
        "url": "https://open.spotify.com/artist/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Mixi",
        "url": "https://mixi.jp/show_profile.pl?id={username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Amino",
        "url": "https://aminoapps.com/u/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Badoo",
        "url": "https://badoo.com/profile/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Bumble",
        "url": "https://bumble.com/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Zillow",
        "url": "https://www.zillow.com/profile/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Zomato",
        "url": "https://www.zomato.com/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Strava",
        "url": "https://www.strava.com/athletes/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "MapMyRun",
        "url": "https://www.mapmyrun.com/profile/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Crunchyroll",
        "url": "https://www.crunchyroll.com/user/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Funimation",
        "url": "https://www.funimation.com/users/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "LiveJournal",
        "url": "https://{username}.livejournal.com",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Ask.fm",
        "url": "https://ask.fm/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Weibo",
        "url": "https://weibo.com/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Plurk",
        "url": "https://www.plurk.com/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Skyrock",
        "url": "https://{username}.skyrock.com",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "NPMJS",
        "url": "https://www.npmjs.com/~{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Packagist",
        "url": "https://packagist.org/users/{username}/",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "RubyGems",
        "url": "https://rubygems.org/profiles/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "Crates.io",
        "url": "https://crates.io/users/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
    {
        "name": "PyPI",
        "url": "https://pypi.org/user/{username}",
        "check_type": "status_code",
        "match": [200],
        "exclude": [404],
    },
]


lock = threading.Lock()


def _check_site(site, username, timeout):
    """Check a single site for the username."""
    if site["check_type"] == "custom":
        return {"site": site["name"], "status": "skipped", "url": site["url"]}

    url = site["url"].format(username=username)
    try:
        resp = check_username_url(url, username, timeout=timeout)
        if resp is None:
            return {"site": site["name"], "status": "error", "url": url}

        status_code = resp.status_code
        if status_code in site["match"]:
            return {"site": site["name"], "status": "found", "url": url}
        elif status_code in site.get("exclude", [404]):
            return {"site": site["name"], "status": "not_found", "url": url}
        else:
            return {"site": site["name"], "status": "unknown", "url": url, "code": status_code}
    except Exception:
        return {"site": site["name"], "status": "error", "url": url}


class UsernameRecon(Module):
    """Search for a username across 100+ platforms."""

    name = "username"
    description = "Search username across 100+ social media platforms and websites"

    def run(self, target, workers=20):
        """Run username reconnaissance across all platforms."""
        print_info(f"Searching for username: {target}")
        print_info(f"Checking {len(SITES)} platforms with {workers} threads...")

        found_count = 0
        not_found_count = 0
        error_count = 0

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(_check_site, site, target, self.timeout): site
                for site in SITES
            }
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result["status"] == "found":
                    print_found(f"{result['site']}: {result['url']}")
                    self.add_result(result["site"], result["url"], "found")
                    found_count += 1
                elif result["status"] == "not_found":
                    print_not_found(f"{result['site']}: not found")
                    not_found_count += 1
                elif result["status"] == "skipped":
                    pass
                else:
                    error_count += 1

        from reconx.utils.output import print_summary
        print_summary(found_count, not_found_count, error_count)

        return self.results
