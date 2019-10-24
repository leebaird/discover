#!/bin/bash

clear
f_banner

echo -e "${BLUE}Create a free account at salesforce (https://connect.data.com/login).${NC}"
echo -e "${BLUE}Perform a search on your target > select the company name > see all.${NC}"
echo -e "${BLUE}Copy the results into a new file.${NC}"
echo -e "${BLUE}[*] Note: each record should be on a single line.${NC}"

f_location

echo

# Remove blank lines, strings, and leading white space. Set tab as the delimiter
cat $location | sed '/^$/d; s/Direct Dial Available//g; s/[] 	//g; s/^[ \t]*//; s/ \+ /\t/g' > tmp

# Place names into a file and sort by uniq
cut -d $'\t' -f1 tmp | sort -u > tmp2

# grep name, sort by data field, then uniq by the name field - selecting the most recent entry
# select and and title from result and colon delimit into file
while read line; do
    grep "$line" tmp | sort -t ',' -k7M | sort -uk1,1r | awk -F$'\t' '{print $1":"$3}' | sed 's/ :/:/g' >> tmp3
done < tmp2

column -s ':' -t tmp3 > tmp4

# Clean-up
cat tmp4 | sed 's/ -- /, /g; s/ - /, /g; s/,,/,/g; s/, ,/, /g; s/\//, /g; s/[^ ]\+/\L\u&/g; s/-.*$//g; s/1.*$//g; s/1/I/g; s/2/II/g; s/3/III/g; s/4/IV/g; s/5/V/g; 
s/2cfinancedistributionoperations//g; s/-administration/, Administration/g; s/-air/, Air/g; s/, ,  and$//g; s/ And / and /g; s/ at.*$//g; s/ asic / ASIC /g; s/ Asm/ ASM/g; 
s/ api / API /g; s/AssistantChiefPatrolAgent/Assistant Chief Patrol Agent/g; s/-associate/-associate/g; s/ at .*//g; s/ At / at /g; s/ atm / ATM /g; s/ bd / BD /g; 
s/-big/, Big/g; s/BIIb/B2B/g; s/-board/, Board/g; s/-boiler/, Boiler/g; s/ bsc / BSC /g; s/-call/, Call/g; s/-capacity/, Capacity/g; s/-cash/, Cash/g; s/ cbt / CBT /g; 
s/ Cc/ CC/g; s/-chief/, Chief/g; s/ cip / CIP /g; s/ cissp / CISSP /g; s/-civil/, Civil/g; s/ cj / CJ /g; s/Clients//g; s/ cmms / CMMS /g; s/ cms / CMS /g; 
s/-commercial/, Commercial/g; s/CommitteemanagementOfficer/Committee Management Officer/g; s/-communications/, Communications/g; s/-community/, Community/g;
s/-compliance/, Compliance/g; s/-consumer/, Consumer/g; s/contact sold, to//g; s/-corporate/, Corporate/g; s/ cpa/ CPA/g; s/-creative/, Creative/g; s/ Crm / CRM /g; 
s/ Csa/ CSA/g; s/ Csc/ CSC/g; s/ctr /Center/g; s/-customer/, Customer/g; s/Datapower/DataPower/g; s/-data/, Data/g; s/ db2 / DB2 /g; s/ dbii / DB2 /g; s/ Dc/ DC/g; 
s/DDesigner/Designer/g; s/DesignatedFederalOfficial/Designated Federal Official/g; s/-design/, Design/g; s/dhs/DHS/g; s/-digital/, Digital/g; 
s/-distribution/, Distribution/g; s/ Disa / DISA /g; s/ dns / DNS /g; s/-dominion/-dominion/g; s/-drilling/, Drilling/g; s/ dvp / DVP /g; s/ ebs / EBS /g; s/ Edi / EDI /g; 
s/editorr/Editor/g; s/ edrm / EDRM /g; s/ eeo / EEO /g; s/ efi / EFI /g; s/-electric/, Electric/g; s/EleCenterEngineer/Electric Engineer/g; s/ emc / EMC /g; s/ emea/ EMEA/g; 
s/-employee/, Employee/g; s/ ems / EMS /g; s/-energy/, Energy/g; s/engineer5/Engineer V/g; s/-engineering/, Engineering/g; s/-engineer/, Engineer/g; 
s/-environmental/, Environmental/g; s/-executive/, Executive/g; s/faa / FAA /g; s/-facilities/, Facilities/g; s/ Fdr / FDR /g; s/ ferc / FERC /g; s/ fha / FHA /g; 
s/-finance/, Finance/g; s/-financial/, Financial/g; s/-fleet/, Fleet/g; s/ For / for /g; s/ fsa / FSA /g; s/ fso / FSO /g; s/ fx / FX /g; s/ gaap / GAAP /g; s/-gas/, Gas/g; 
s/-general/, General/g; s/-generation/, Generation/g; s/grp/Group/g; s/ gsa / GSA /g; s/ gsis / GSIS /g; s/ gsm / GSM /g; s/Hbss/HBSS/g; s/ hd / HD /g; s/ hiv / HIV /g; 
s/ hmrc / HMRC /g; s/ hp / HP /g; s/ hq / HQ /g; s/ hris / HRIS /g; s/-human/, Human/g; s/ hvac / HVAC /g; s/ ia / IA /g; s/ id / ID /g; s/ iii/ III/g; s/ Ii/ II/g; 
s/ Iis / IIS /g; s/ In / in /g; s/-industrial/, Industrial/g; s/information technology/IT/g; s/-information/, Information/g; s/-infrastructure/, Infrastructure/g; 
s/-instrumentation/, Instrumentation/g; s/-internal/, Internal/g; s/ ip / IP /g; s/ ir / IR /g; s/ Issm/ ISSM/; s/itenterpriseprojectmanager/IT Enterprise Project Manager/g; 
s/-IT/, IT/g; s/ iv / IV /g; s/ Iv,/ IV,/g; s/Jboss/JBoss/g; s/ jc / JC /g; s/ jd / JD /g; s/ jt / JT /g; s/konsult, konsultchef, projektledare/Consultant/g; 
s/laboratorynetwork/Laboratory, Network/g; s/-labor/, Labor/g; s/lan administrator/LAN Administrator/g; s/lan admin/LAN Admin/g; s/-land/, Land/g; s/-licensing/, Licensing/g; 
s/LawIII60/Law360/g; s/ llc / LLC. /g; s/-logistics/, Logistics/g; s/ Lp/ LP/g; s/lvl/Level/g; s/-mail/, Mail/g; s/-manager/, Manager/g; s/-marketing/, Marketing/g; 
s/-materials/, Materials/g; s/ mba / MBA /g; s/Mca/McA/g; s/Mcb/McB/g; s/Mcc/McC/g; s/Mcd/McD/g; s/Mce/McE/g; s/Mcf/McF/g; s/Mcg/McG/g; s/Mch/McH/g; s/Mci/McI/g; s/Mcj/McJ/g; 
s/Mck/McK/g; s/Mcl/McL/g; s/Mcm/McM/g; s/Mcn/McN/g; s/Mcp/McP/g; s/Mcq/McQ/g; s/Mcs/McS/g; s/Mcv/McV/g; s/mcse/MCSE/g; s/-mechanical/, Mechanical/g; s/-metals/, Metals/g; 
s/-metro/, Metro/g; s/, mp//g; s/ nerc / NERC /g; s/mcp/McP/g; s/mcq/McQ/g; s/mcs/McS/g; s/-media/, Media/g; s/-mergers/,Mergers/g; s/-millstone/, Millstone/g; 
s/-motor/, Motor/g; s/ mssp / MSSP /g; s/-networking/, Networking/g; s/-network/, Network/g; s/-new/, New/g; s/-north/, North/g; s/not in it//g; s/ nso / NSO /g; 
s/-nuclear/, Nuclear/g; s/ Nz / NZ /g; s/ oem / OEM /g; s/-office/, Office/g; s/ Of / of /g; s/-operations/, Operations/g; s/-oracle/, Oracle/g; s/-other/, Other/g; 
s/ pca / PCA /g; s/ pcs / PCS /g; s/ pc / PC /g; s/ pdm / PDM /g; s/ phd / PhD /g; s/ pj / PJ /g; s/-plant/, Plant/g; s/plt/Plant/g; s/pmo/PMO/g; s/Pmp/PMP/g; s/ pm / PM /g; 
s/ Pm / PM /g; s/-power/, Power/g; s/-property/, Property/g; s/-public/, Public/g; s/ Psa/ PSA/g; s/pyble/Payble/g; s/ os / OS /g; s/r&d/R&D/g; s/ r and d /R&D/g; 
s/-records/, Records/g; s/-regulated/, Regulated/g; s/-regulatory/, Regulatory/g; s/-related/, Related/g; s/-remittance/, Remittance/g; s/-renewals/, Renewals/g; 
s/-revenue/, Revenue/g; s/ rfid / RFID /g; s/ rfp / RFP /g; s/ rf / RF /g; s/ Roip / RoIP /g; s/Rtls/RTLS/g; s/ Rtm/ RTM/g; s/saas/SaaS/g; s/-safety/, Safety/g; 
s/san manager/SAN Manager/g; s/scada/SCADA/g; s/sdlc/SDLC/g; s/setac-/SETAC,/g; s/sftwr/Software/g; s/-short/, Short/g; s/ smb / SMB /g; s/sms/SMS/g; s/smtp/SMTP/g; 
s/snr/Senior/g; s/.specialist./ Specialist /g; s/ Soc / SOC /g; s/sql/SQL/g; s/spvr/Supervisor/g; s/srbranch/Senior Branch/g; s/srsales/Senior Sales/g; s/ ssl / SSL /g; 
s/-staff/, Staff/g; s/stf/Staff/g; s/-station/, Station/g; s/-strategic/, Strategic/g; s/-student/, Student/g; s/-substation/, Substation/g; s/-supplier/, Supplier/g; 
s/-supply/, Supply/g; s/-surveillance/, Surveillance/g; s/swepco/SWEPCO/g; s/-system/, System/g; s/-tax/, Tax/g; s/-technical/, Technical/g; 
s/-telecommunications/, Telecommunications/g; s/ The / the /g; s/-three/, Three/g; s/-tickets/, Tickets/g; s/TierIII/Tier III/g; s/-trading/, Trading/g; 
s/-transmission/, Transmission/g; s/ttechnical/Technical/g; s/-turbine/, Turbine/g; s/ to .*$//g; s/ ui / UI /g; s/ uk / UK /g; s/unsupervisor/Supervisor/g; s/uscg/USCG/g; 
s/ usa / USA /g; s/ us / US /g; s/ Us / US /g; s/ u.s / US /g; s/usmc/USMC/g; s/-utility/, Utility/g; s/ ux / UX /g; s/vicepresident/Vice President/g; s/ Va / VA /g; 
s/ vii / VII /g; s/ vi / VI /g; s/ vms / VMS /g; s/ voip / VoIP /g; s/ vpn / VPN /g; s/Weblogic/WebLogic/g; s/Websphere/WebSphere/g; s/ With / with /g' > tmp5

# Remove lines that contain 2 words and clean up.
awk 'NF != 2' tmp5 | sed "s/d'a/D'A/g; s/d'c/D'C/g; s/d'e/D'E/g; s/d'h/D'H/g; s/d's/D'S/g; s/l'a/L'A/g; s/o'b/O'B/g; s/o'c/O'C/g; s/o'd/O'D/g; s/o'f/O'F/g; s/o'g/O'G/g; 
s/o'h/O'H/g; s/o'k/O'K/g; s/o'l/O'L/g; s/o'm/O'M/g; s/o'N/O'N/g; s/Obrien/O'Brien/g; s/Oconnor/O'Connor/g; s/Odonnell/O'Donnell/g; s/Ohara/O'Hara/g; s/o'p/O'P/g; s/o'r/O'R/g; 
s/o's/O'S/g; s/Otoole/O'Toole/g; s/o't/O'T/i" > tmp6

# Replace parenthesis and the contents inside with spaces - thanks Mike G
cat tmp6 | perl -pe 's/(\(.*\))/q[ ] x length $1/ge' > tmp7

# Remove trailing white space, railing commas, and delete lines with a single word
sed 's/[ \t]*$//; s/,$//; /[[:blank:]]/!d' tmp7 | sort -u > $home/data/names.txt
rm tmp*

echo
echo $medium
echo
echo -e "The new report is located at ${YELLOW}$home/data/names.txt${NC}\n"
echo
echo

