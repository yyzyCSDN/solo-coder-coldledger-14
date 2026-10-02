from datetime import timedelta
from .inventory.fefo import reserve
from .quality.release import may_release
from .transport.connections import choose
from .customs.dossier import assemble_dossier, replay_declarations
class ColdLedgerService:
    def reserve_inventory(self,*args,**kwargs): return reserve(*args,**kwargs)
    def release_decision(self,*args,**kwargs): return may_release(*args,**kwargs)
    def next_connection(self,inbound,candidates,minutes): return choose(inbound,candidates,timedelta(minutes=minutes))
    def assemble_customs_dossier(self,*args,**kwargs): return assemble_dossier(*args,**kwargs)
    def replay_customs_declarations(self,*args,**kwargs): return replay_declarations(*args,**kwargs)
    def health(self): return {'service':'coldledger','status':'ok','runtime_dependencies':0}
