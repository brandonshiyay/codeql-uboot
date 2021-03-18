import cpp

from Macro f
where f.getName().regexpMatch("ntoh(s|l|ll)")
select f, "ntoh*" 


