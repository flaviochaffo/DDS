library(jsonlite)
library(mitre)
library(burro)
library(dplyr)
library(ggplot2)
library(plyr)
library(markdown)
library(knitr)
library(stringr)
library(ggrepel)

i <- 1
while (i<= nrow(CAPECordered))
  {
    aux <- grep(CAPECordered$CAPEC[i],capec.patterns$id)
    CAPECordered$Name[i] <- capecs.patterns$name[aux]
    CAPECordered$Description[i] <- capec.patterns$description[aux]
    CAPECordered$Likelihood[i] <- capec.patterns$likelihood[aux]
    CAPECordered$Severity[i] <- capec.patterns$severity[aux]
    CAPECordered$LikelihoodScore[i] <- switch(CAPECordered$Likelihood[i],"Unknown"=1,"Low"=2,"Medium"=3,"High"=4)
    CAPECordered$SeverityScore[i] <- switch(CAPECordered$Severity[i],"Unknown"=1,"Very Low"=2,"Low"=3,"Medium"=4,"High"=5,"Very High"=6)
    CAPECordered$RiskScore[i] <- CAPECordered$LikelihoodScore[i]*CAPECordered$SeverityScore[i]

    if (CAPECordered$RiskScore[i]<=6){
      CAPECordered$Risk[i] <- "Low"
    }
    if ((CAPECordered$RiskScore[i]>6)&(CAPECordered$RiskScore[i]<=12)){

      CAPECordered$Risk[i] <- "Medium"
    }
    if ((CAPECordered$RiskScore[i]>12)&(CAPECordered$RiskScore[i]<18)){

      CAPECordered$Risk[i] <- "High"
    }
    if (CAPECordered$RiskScore[i]>=18){

      CAPECordered$Risk[i] <- "Critical"
    }

    i <- i + 1
}


plot <- ggplot(CAPECordered, aes(x = Likelihood, y = Severity)) + geom_tile(aes(fill= Risk)) + scale_fill_manual(breaks = c("Critical","High","Medium","Low"),values = c("Red","Orange","Yellow","Green"))
plot + scale_x_discrete(limit = c("Unknown", "Low", "Medium","High"))+
  scale_y_discrete(limit = c("Unknown","Very Low", "Low", "Medium","High","Very High")) + geom_label_repel(label=CAPECordered$CAPEC,
                                                                                          nudge_x = 0, nudge_y = 0,
                                                                                          size =3, max.overlaps = 139)
capecs.relations <- file.show("capec.relations.rda")

