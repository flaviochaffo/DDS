library(jsonlite)
library(mitre)
library(burro)
library(dplyr)
library(ggplot2)
library(plyr)
library(markdown)
library(knitr)
library(stringr)

cpeordered[1,3]                                       #Muestro cuantos CVE tiene el primer CPE
aux <- nrow(cpeordered)                               #Cuento todas las líneas de CPEs

CVE <- data.frame(cpeordered$vuln[1])                 #Llevo a un nuevo dataframe todas los CVEs del primer CPE
colnames(CVE) <- "CVEs"                               #Le pongo de nombre a la columna CVEs
i <- 2                                                #Auxiliar en 2

while (i <= aux){                                     #Voy añadiendo al dataframe anterior todas las listas de CVEs que existen en el dataframe CPE

  CVE2 <- data.frame(cpeordered$vuln[i])
  colnames(CVE2) <- "CVEs"
  CVE <- rbind(CVE,CVE2)
  distinct(CVE)
  i <- i + 1
}

i <- 2

while (i <= nrow(CVE)){
  j <- i - 1

  while (j > 0){

    if (CVE[i,1] == CVE[j,1]){

      CVE[i,1] <- 0
   }
    j <- j - 1

  }

  i <- i + 1
}

CVEf <- data.frame(CVE[1,1])
colnames(CVEf) <- "CVEs"
i <- 2

while (i <= nrow(CVE)){

  if(CVE[i,1] != 0){
    CVEf <- rbind(CVEf,CVE[i,1])
  }

  i <- i + 1
}

CVEf$total <- lapply(lapply(CVEf[,1],cpeordered$vuln,FUN = grep), length)
CVEf$pos <- lapply(CVEf[,1],cpeordered$vuln,FUN = grep)
CVEf$total <- as.numeric(CVEf[,2])
CVEordered <- CVEf[order(CVEf$total,decreasing = TRUE),]

producto <- "Rockwell"

topcve <- CVEordered[1:30,]
color <- c(1:nrow(topcve))

graphic1 <- ggplot(data = topcve, mapping = aes(x = total, y = CVEs, fill = as.factor(color)))

graphic1 + geom_bar(stat = 'identity') +
  xlab("Total de CPEs") +
  ylab("CVE") +
  ggtitle(paste("Gráfico de los TOP 30 Vulnerabilidades en",producto,sep = " ")) +
  labs(fill = "CVEs")


jason <- paste("https://services.nvd.nist.gov/rest/json/cve/1.0/",topcve[1,1],sep="")
api <- fromJSON(jason)

CVEordered$severity <- ""
CVEordered$score <- 0
CVEordered$version <- ""
CVEordered$time <- ""
CVEordered$description <- ""
CVEordered$CWE <- ""

i <- 1

while (i<=nrow(CVEordered)){

  jason <- paste("https://services.nvd.nist.gov/rest/json/cve/1.0/",CVEordered[i,1],sep="")
  api <- fromJSON(jason)
  try(
    {
    options(show.error.messages = FALSE)
    CVEordered$severity[i] <- api$result$CVE_Items$impact$baseMetricV3$cvssV3$baseSeverity
    CVEordered$score[i] <- api$result$CVE_Items$impact$baseMetricV3$cvssV3$baseScore
    CVEordered$version[i] <- "cvssV3"
    options(show.error.messages = TRUE)
    },silent = TRUE
  )
  if (CVEordered$severity[i] == "")
  {
    CVEordered$severity[i] <- api$result$CVE_Items$impact$baseMetricV2$severity
    CVEordered$score[i] <- api$result$CVE_Items$impact$baseMetricV2$cvssV2$baseScore
    CVEordered$version[i] <- "cvssV2"
  }
  CVEordered$time[i] <- api$result$CVE_Items$lastModifiedDate
  CVEordered$description[i] <- unlist(list(api$result$CVE_Items$cve$description$description_data))[2]
  CVEordered$CWE[i] <- unlist(list(api$result$CVE_Items$cve$problemtype$problemtype_data))[2]

  i <- i + 1
  Sys.sleep(5)
}

CVEorderedtop <- CVEordered[1:40,]

graphic2 <- ggplot(data = CVEorderedtop, mapping = aes(score,CVEs))

graphic2 + geom_point() + # Show dots

  geom_label(
    label=CVEorderedtop$CWE,
    nudge_x = 0.25, nudge_y = 0.25,
  ) +
  xlab("CVSS score") +
  ylab("CVE") +
  ggtitle(paste("Gráfico de los CVEs vs CVSS Score",producto,sep = " ")) +
  labs(fill = "CVEs")

cwes <- file.show("cwes.rda")
