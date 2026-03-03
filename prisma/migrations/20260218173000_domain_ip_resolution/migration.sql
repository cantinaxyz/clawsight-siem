-- CreateTable
CREATE TABLE "DomainIpResolution" (
    "id" SERIAL NOT NULL,
    "domain" TEXT NOT NULL,
    "domainHash" TEXT NOT NULL,
    "ip" TEXT NOT NULL,
    "ipHash" TEXT NOT NULL,
    "source" TEXT NOT NULL DEFAULT 'dns',
    "hits" INTEGER NOT NULL DEFAULT 1,
    "firstSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "DomainIpResolution_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "DomainIpResolution_domainHash_ipHash_source_key"
  ON "DomainIpResolution"("domainHash", "ipHash", "source");

-- CreateIndex
CREATE INDEX "DomainIpResolution_domainHash_lastSeenAt_idx"
  ON "DomainIpResolution"("domainHash", "lastSeenAt" DESC);

-- CreateIndex
CREATE INDEX "DomainIpResolution_ipHash_lastSeenAt_idx"
  ON "DomainIpResolution"("ipHash", "lastSeenAt" DESC);

-- CreateIndex
CREATE INDEX "DomainIpResolution_lastSeenAt_idx"
  ON "DomainIpResolution"("lastSeenAt" DESC);
