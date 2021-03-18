import cpp

from Function f
where f.getName().regexpMatch("ntoh(s|l|ll)")
select f, "ntoh*" 


