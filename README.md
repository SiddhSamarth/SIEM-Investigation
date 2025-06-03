# SIEM-Investigation

## Objective

The SIEM Investigation project sought to deepen the understanding of Sentinel SIEM's investigative and informative capabilities as well as aiming to optimize its functionalities for comprehensive incident analysis and response.

## Skills Learned

- Proficiency in log analysis and correlation for identifying suspicious activities.
- Enhanced skills in real-time event monitoring and threat detection.
- Capability to conduct forensic investigations using Sentinel's comprehensive data collection.
- Expertise in creating and fine-tuning alerts for proactive threat identification.
- Mastery in proactive threat hunting through Sentinel SIEM's advanced search and query capabilities.
- Enhanced skills in leveraging threat intelligence feeds to enrich and contextualize security data.

## Tools Used

- Azure Sentinel (SIEM) for investigating & threat hunting

## Steps

**1. Open Azure portal navigate to Sentinel workspace & go to **Incident** view of the Sentinel workspace.**

**2. From the list select "Solorigate Network Beacon" incident.**

![1](https://github.com/laaaaaarry/SIEM-Investigation/assets/125237930/b1c367b8-568b-4102-82a2-ff276a374558)


**3. Assign the incident to yourself & click Apply.**

![2](https://github.com/laaaaaarry/SIEM-Investigation/assets/125237930/9fc13235-f03f-401e-8eb4-8264ec56c4f9)


**4. Read the description of the incident. As you can see, one of the domain IOCs related to Solorigate attack has been found. In this case, domain avsvmcloud.com is involved.**

![3](https://github.com/laaaaaarry/SIEM-Investigation/assets/125237930/da5dbf74-9300-4560-84da-855c06f85702)

![image](https://github.com/laaaaaarry/SIEM-Investigation/assets/125237930/adc0a8e5-03e1-40ef-ab3e-1e050a8c17da)
   
**5. Optionally, you can click on View full details to drill down to inspect the raw events that triggered this alert. For that, click an Alert in the timeline, and click on Link to LA.**

![4](https://github.com/laaaaaarry/SIEM-Investigation/assets/125237930/c3d94d2c-dfcf-4527-b59d-b34cc71b907e)

![Screenshot 2024-03-08 234033](https://github.com/laaaaaarry/SIEM-Investigation/assets/125237930/5ee7f05f-eb95-45c9-954d-2e57250ff3b4)

**6. As you can see, the events originated in Cisco Umbrella DNS, and the analytic rule uses Advanced Security Information Model (ASIM) to normalize these events from any DNS source.**

![Screenshot 2024-03-08 234130](https://github.com/laaaaaarry/SIEM-Investigation/assets/125237930/6d5b9903-7ebe-4441-950a-60b58fec797e)

**7. Next we will try to identify hosts which might have been compromised. Click on Hunting tab on Sentinel Menu & select Queries tab if not selected.**

![5](https://github.com/laaaaaarry/SIEM-Investigation/assets/125237930/99b7cb15-6b29-49c8-935c-706e5d8b4593)


**8. In the search box, type "solorigate". Select the Solorigate Inventory check query and click on Run Query.**

![6](https://github.com/laaaaaarry/SIEM-Investigation/assets/125237930/fdc5c3db-9f3a-4a72-9fea-ee4549c293e6)


**9. You should see a total of three results. Click on View Results**

![7](https://github.com/laaaaaarry/SIEM-Investigation/assets/125237930/6b21bbc7-90a7-4a8b-9a8b-1bea2e9591c8)

**10. As you can see, besides ClientPC, there are two additional computers where the malicious DLL and named pipe have been found. Bookmark all three records, by selecting them with the tickboxes on the left, and clicking on Add bookmark.**

![8](https://github.com/laaaaaarry/SIEM-Investigation/assets/125237930/80821e0a-4997-4e10-a1fa-5e3d98228f38)


**11. In the Add bookmarks window that appears, click on Create to create the bookmarks. As you can see entity mapping is already done for you.**

![Screenshot 2024-03-08 235534](https://github.com/laaaaaarry/SIEM-Investigation/assets/125237930/16fa33df-8e5a-41fa-9e3b-183b08a1c6a4)

**12. Now close log search you will be in Bookmark tab where we can see 2 new bookmarks created. Select both & click add on incident actions at top & add to existing incident.**

![9](https://github.com/laaaaaarry/SIEM-Investigation/assets/125237930/2f4145ae-6040-4fa6-b40d-18766a6127eb)

![10](https://github.com/laaaaaarry/SIEM-Investigation/assets/125237930/1d114523-c534-4f80-b221-b1e341766c56)


**13. From the list, pick the Solorigate incident that is assigned to you, and click Add.**

![Screenshot 2024-03-09 000107](https://github.com/laaaaaarry/SIEM-Investigation/assets/125237930/728559ca-2e8c-4a61-b326-1d02f9b35cd5)

**14. Now, we will add the IP address related to the incident to our list of Indicators of Compromise (IOC) in our Sentinel workspace Threat Intelligence store, so we can capture any new occurrences of this IOC across our logs.**

**15. Go back to the Incidents view. Select the Solorigate incident and copy the IP address involved. Notice that you now have more computer entities available for selection, as they were added to the incident from the bookmarks' entities.**

![Screenshot 2024-03-09 000506](https://github.com/laaaaaarry/SIEM-Investigation/assets/125237930/25602c01-9a2a-488a-9aaf-4d440957748c)


**16. Go to the Threat Intelligence blade in Microsoft Sentinel and click Add new at the top.**

![11](https://github.com/laaaaaarry/SIEM-Investigation/assets/125237930/410c2584-2cb4-45ef-bba6-7b7227de9e54)

**17. Enter the following details in the New indicator dialog, with Valid from being today's date and Valid until being two months after. Then click Apply.**

![incident12](https://github.com/laaaaaarry/SIEM-Investigation/assets/125237930/eded5373-d298-4208-850f-73bb54907730)

**18. We will now prepare the incident for handover to another team (maybe Operations or Forensics) by ensuring what we've done is documented.**

**19. Go to Incidents & select the Solorigate incident assigned to you. Click on View full details. Move to Comments tab.**

![incident13](https://github.com/laaaaaarry/SIEM-Investigation/assets/125237930/e8b62ad2-09cb-4c91-86f1-92fe08d8bf35)

**20. Enter information about all the steps performed.**

![incident14](https://github.com/laaaaaarry/SIEM-Investigation/assets/125237930/92e087aa-a887-41df-8b5a-a5f20059dfd3)




## Documentation

* IOC detected, **avsvmcloud.com** domain is detected which is indicator of Solorigate attack.

* Source address of the attack was **17.81.146.1**

* Event was recorded by **Cisco Umbrella DNS**

* Event start time was **2019-09-12 T20:00:00.625Z**

* Attack infected 3 hosts : **AdminPc.Contoso.Azure**, **ClientPc.Contoso.Azure**, **VictimPc.Contoso.Azure**

* Attack IP **17.81.146.1** was uploaded to Online Threat Intelligence
