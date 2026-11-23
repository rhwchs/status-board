# Status Board

A small page that checks public data sources (weather alerts, flight status, power and internet outage reports,
markets, news) and summarises them on one screen, with a link to every original source.

The page is private. It is rebuilt automatically on a schedule by a GitHub Actions job and published with GitHub Pages;
it needs an access code to open. Not for safety-critical decisions.

The job needs two repository secrets: `ACCESS_CODE` (the code that unlocks the page) and `EIA_API_KEY` (a free key from
eia.gov for grid data).
