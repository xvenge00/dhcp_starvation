# IPK projekt 2
## DHCP starvation útok
Program sa pokúsi vyčerpať IP pool DHCP servera.

Pre správnu činnosť musí byť program spustný s root právami.

Spustenie:
`./ipk-dhcpstarve -i interface`

### Nedostatky
Účinnosť útoku závisí na nastavení DHCP serveru.
Pri správnom nastavení je program neúčinný.

Odosielané packety majú v IP hlavičke IP adresu útočníka.
